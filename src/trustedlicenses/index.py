"""Ask a package index whether a newer release of a package ships a license.

Opt-in only: nothing in a plain ``trustedlicenses`` run imports or calls this. It exists
because the usual remedy for "no license information found" is an upgrade -- e.g.
``webencodings`` 0.5.1 bundles no license file, 0.6.0 and later do -- and the index is the
only place that can say so.

Works against any index speaking the standard "simple" API (:pep:`503`), preferring the
JSON form (:pep:`691`) and, per release, the small separate metadata file (:pep:`658`)
over downloading a whole wheel. Only the package *name* is ever sent.

Credentials are not managed here: they come from the user's environment (``user:pass@``
in the index URL, or ``.netrc``), and are dropped if the index redirects to another host.
"""

from __future__ import annotations

import contextlib
import email
import io
import json
import netrc
import os
import ssl
import urllib.error
import urllib.request
import zipfile
from base64 import b64encode
from dataclasses import dataclass
from fnmatch import fnmatch
from html.parser import HTMLParser
from typing import TYPE_CHECKING, Protocol
from urllib.parse import unquote, urljoin, urlsplit, urlunsplit

from packaging.utils import (
    InvalidSdistFilename,
    InvalidWheelFilename,
    canonicalize_name,
    parse_sdist_filename,
    parse_wheel_filename,
)
from packaging.version import InvalidVersion, Version

from trustedlicenses.detection import LICENCE_FILE_PATTERNS, resolve_license_expression
from trustedlicenses.index_discovery import redact_url

if TYPE_CHECKING:
    from http.client import HTTPMessage
    from typing import IO

TIMEOUT_SECONDS = 20.0
MAX_WHEEL_BYTES = 25 * 1024 * 1024
MAX_VERSIONS_CHECKED = 10
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_NOT_FOUND = 404
_ACCEPT = "application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1"


class IndexQueryError(Exception):
    """A query failed in a way the user can act on; ``str(error)`` is the explanation."""


class IndexHttpError(IndexQueryError):
    """The index answered with an HTTP error status."""

    def __init__(self, status: int, message: str) -> None:
        """Record the status alongside the message.

        Args:
            status: The HTTP status code.
            message: The user-facing explanation.
        """
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Response:
    """A fetched document.

    Attributes:
        url: The final URL after any redirects (relative links resolve against this).
        content_type: The response's ``Content-Type``.
        body: The raw bytes.
    """

    url: str
    content_type: str
    body: bytes


class Client(Protocol):
    """What :func:`audit_package` needs from a network layer -- fakeable in tests."""

    def get(self, url: str, *, accept: str | None = None, max_bytes: int | None = None) -> Response:
        """Fetch ``url``, raising :class:`IndexQueryError` on any failure."""
        ...

    def credentials_for(self, url: str) -> str:
        """Describe where credentials for ``url`` come from, for the report."""
        ...


class _DropAuthOnCrossHostRedirect(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never forward credentials to a different host."""

    def redirect_request(  # noqa: PLR0913, PLR0917 -- signature fixed by urllib
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urlsplit(newurl).netloc != urlsplit(req.full_url).netloc:
            new.remove_header("Authorization")
        return new


def _basic(user: str, password: str) -> str:
    return "Basic " + b64encode(f"{user}:{password}".encode()).decode()


class HttpClient:
    """The real network layer: stdlib ``urllib``, honouring proxy and CA environment settings."""

    def __init__(self) -> None:
        """Build an opener that drops credentials on cross-host redirects."""
        self._opener = urllib.request.build_opener(_DropAuthOnCrossHostRedirect)
        # Credentials given in the index URL, remembered per host: file links on the
        # index page come back without them, but need them to download from that host.
        self._url_credentials: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _netrc_login(host: str) -> tuple[str, str] | None:
        path = os.environ.get("NETRC")
        try:
            entry = netrc.netrc(path).authenticators(host)
        except (OSError, netrc.NetrcParseError):
            return None
        return (entry[0], entry[2] or "") if entry else None

    def _credentials(self, url: str) -> tuple[str, str] | None:
        parts = urlsplit(url)
        if parts.username is not None:
            self._url_credentials[parts.netloc.rsplit("@", 1)[-1]] = (
                unquote(parts.username),
                unquote(parts.password or ""),
            )
        return self._url_credentials.get(parts.netloc.rsplit("@", 1)[-1]) or self._netrc_login(parts.hostname or "")

    def credentials_for(self, url: str) -> str:
        """Describe where credentials for ``url`` come from.

        Args:
            url: An index URL.

        Returns:
            ``"in the index URL"``, ``".netrc"`` or ``"none"``.
        """
        if urlsplit(url).username is not None or urlsplit(url).netloc in self._url_credentials:
            return "in the index URL"
        return ".netrc" if self._netrc_login(urlsplit(url).hostname or "") else "none"

    def get(self, url: str, *, accept: str | None = None, max_bytes: int | None = None) -> Response:
        """Fetch a URL, with credentials from the environment.

        Args:
            url: An ``http(s)`` URL, possibly with ``user:pass@``.
            accept: Optional ``Accept`` header.
            max_bytes: Refuse bodies larger than this.

        Returns:
            The fetched document.

        Raises:
            IndexHttpError: The server returned an HTTP error status.
            IndexQueryError: Any other failure (network, TLS, timeout, too large).
        """
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            message = f"Refusing to fetch non-http(s) URL: {redact_url(url)}"
            raise IndexQueryError(message)
        headers = {"Accept": accept} if accept else {}
        if credentials := self._credentials(url):
            headers["Authorization"] = _basic(*credentials)
        clean = urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1]))
        request = urllib.request.Request(clean, headers=headers)  # noqa: S310 -- scheme checked above
        try:
            with self._opener.open(request, timeout=TIMEOUT_SECONDS) as response:
                body = response.read(max_bytes + 1) if max_bytes else response.read()
                final_url, content_type = response.url, response.headers.get("Content-Type", "")
        except urllib.error.HTTPError as error:
            raise IndexHttpError(error.code, _http_message(error.code, clean)) from error
        except urllib.error.URLError as error:
            raise IndexQueryError(_network_message(error, clean)) from error
        except TimeoutError as error:
            message = f"Timed out after {TIMEOUT_SECONDS:.0f}s waiting for {redact_url(clean)}."
            raise IndexQueryError(message) from error
        if max_bytes and len(body) > max_bytes:
            message = f"{redact_url(clean)} is larger than {max_bytes // (1024 * 1024)} MB; not downloading it."
            raise IndexQueryError(message)
        return Response(url=final_url, content_type=content_type, body=body)


def _http_message(status: int, url: str) -> str:
    shown = redact_url(url)
    if status in (_HTTP_UNAUTHORIZED, _HTTP_FORBIDDEN):
        return (
            f"{shown} rejected the request ({status}). Credentials are read from your environment "
            "(user:pass@ in the index URL, or .netrc) -- this tool doesn't manage them."
        )
    if status == _HTTP_NOT_FOUND:
        return f"{shown} not found on this index (a package that isn't published there, e.g. an internal one)."
    return f"{shown} returned HTTP {status}."


def _network_message(error: urllib.error.URLError, url: str) -> str:
    if isinstance(error.reason, ssl.SSLError):
        return (
            f"TLS verification failed for {redact_url(url)}: {error.reason}. If your index uses a private CA, "
            "point SSL_CERT_FILE at its certificate bundle."
        )
    return f"Could not reach {redact_url(url)}: {error.reason}."


@dataclass(frozen=True)
class IndexFile:
    """One downloadable file listed on an index page.

    Attributes:
        filename: The distribution filename.
        url: Absolute URL of the file.
        has_metadata: Whether the index advertises a separate metadata file (:pep:`658`).
    """

    filename: str
    url: str
    has_metadata: bool


class _LinkParser(HTMLParser):
    """Collect ``<a>`` links from a :pep:`503` page, with their :pep:`658`/yank attributes."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[dict[str, str | None]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            self.links.append(dict(attrs))


def _files_from_json(response: Response) -> list[IndexFile]:
    files = []
    for entry in json.loads(response.body).get("files", []):
        if entry.get("yanked"):
            continue
        advertised = entry.get("core-metadata") or entry.get("dist-info-metadata")
        files.append(IndexFile(entry["filename"], urljoin(response.url, entry["url"]), bool(advertised)))
    return files


def _files_from_html(response: Response) -> list[IndexFile]:
    parser = _LinkParser()
    parser.feed(response.body.decode("utf-8", errors="replace"))
    files = []
    for link in parser.links:
        href = link.get("href")
        if not href or link.get("data-yanked") is not None:
            continue
        advertised = link.get("data-core-metadata") or link.get("data-dist-info-metadata")
        filename = unquote(urlsplit(href).path.rsplit("/", 1)[-1])
        files.append(IndexFile(filename, urljoin(response.url, href), advertised is not None))
    return files


def _project_files(client: Client, index_url: str, package: str) -> tuple[list[IndexFile], bool]:
    page_url = index_url.rstrip("/") + "/" + canonicalize_name(package) + "/"
    response = client.get(page_url, accept=_ACCEPT)
    if "json" in response.content_type:
        return _files_from_json(response), True
    return _files_from_html(response), False


def _releases(files: list[IndexFile]) -> dict[Version, list[IndexFile]]:
    releases: dict[Version, list[IndexFile]] = {}
    for file in files:
        version = None
        with contextlib.suppress(InvalidWheelFilename, InvalidSdistFilename, InvalidVersion):
            version = (
                parse_wheel_filename(file.filename)[1]
                if file.filename.endswith(".whl")
                else parse_sdist_filename(file.filename)[1]
            )
        if version is not None:
            releases.setdefault(version, []).append(file)
    return releases


def _pick_wheel(files: list[IndexFile]) -> IndexFile | None:
    wheels = [file for file in files if file.filename.endswith(".whl")]
    pure = [file for file in wheels if file.filename.endswith("-none-any.whl")]
    return next(iter(pure or wheels), None)


def _evidence(metadata_text: str, dist_info_names: list[str]) -> str | None:
    """Say why a release counts as shipping a detectable license, or ``None``."""
    message = email.message_from_string(metadata_text)
    if license_files := message.get_all("License-File"):
        return f"License-File: {', '.join(license_files)}"
    statements = [
        *(message.get_all("License-Expression") or []),
        *(value for value in (message.get_all("License") or []) if "\n" not in value),
        *(value for value in (message.get_all("Classifier") or []) if value.startswith("License ::")),
    ]
    resolved = set().union(*(resolve_license_expression(statement) for statement in statements))
    if resolved:
        return "declares " + ", ".join(sorted(resolved))
    bundled = [
        name
        for name in dist_info_names
        if any(fnmatch(name.rsplit("/", 1)[-1].upper(), pattern) for pattern in LICENCE_FILE_PATTERNS)
    ]
    return f"bundles {bundled[0].rsplit('/', 1)[-1]}" if bundled else None


def _metadata_url(file_url: str) -> str:
    parts = urlsplit(file_url)
    return urlunsplit(parts._replace(path=parts.path + ".metadata", fragment=""))


@dataclass(frozen=True)
class VersionFinding:
    """What one release of the package declares.

    Attributes:
        version: The release.
        evidence: Why it counts as shipping a detectable license, or ``None``.
        note: Why it couldn't be inspected, if it couldn't.
    """

    version: Version
    evidence: str | None
    note: str | None = None


def _inspect(client: Client, version: Version, files: list[IndexFile]) -> VersionFinding:
    wheel = _pick_wheel(files)
    if wheel is None:
        return VersionFinding(version, None, "only a source distribution is published; can't inspect it cheaply")
    if wheel.has_metadata:
        with contextlib.suppress(IndexHttpError):
            text = client.get(_metadata_url(wheel.url)).body.decode("utf-8", errors="replace")
            return VersionFinding(version, _evidence(text, []))
    try:
        body = client.get(wheel.url, max_bytes=MAX_WHEEL_BYTES).body
    except IndexQueryError as error:
        return VersionFinding(version, None, str(error))
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        names = [name for name in archive.namelist() if ".dist-info/" in name]
        metadata = next((name for name in names if name.endswith(".dist-info/METADATA")), None)
        text = archive.read(metadata).decode("utf-8", errors="replace") if metadata else ""
    return VersionFinding(version, _evidence(text, names))


@dataclass(frozen=True)
class Audit:
    """The outcome of asking an index about one package.

    Attributes:
        index_url: The index asked.
        package: The package name.
        installed: The installed version string ("" if unknown).
        served_json: Whether the index answered in JSON (:pep:`691`).
        has_metadata: Whether any release advertises separate metadata (:pep:`658`).
        credentials: Where credentials came from (see :meth:`Client.credentials_for`).
        first_with_license: The oldest *newer* release that ships a license, if any.
        latest: The newest release inspected (``None`` when nothing is newer).
        newer_count: How many newer releases the index lists.
        checked: How many of them were inspected.
    """

    index_url: str
    package: str
    installed: str
    served_json: bool
    has_metadata: bool
    credentials: str
    first_with_license: VersionFinding | None
    latest: VersionFinding | None
    newer_count: int
    checked: int


def audit_package(
    client: Client,
    index_url: str,
    package: str,
    installed_version: str,
    *,
    max_versions: int = MAX_VERSIONS_CHECKED,
) -> Audit:
    """Find the first release newer than the installed one that ships a license.

    Args:
        client: The network layer.
        index_url: The index's simple-API URL.
        package: The package name.
        installed_version: The installed version, or ``""`` to consider every release.
        max_versions: How many newer releases to inspect, oldest first, before stopping.

    Returns:
        What the index says.

    Raises:
        IndexQueryError: The index couldn't be queried (see the exception message).
    """
    files, served_json = _project_files(client, index_url, package)
    releases = _releases(files)
    try:
        installed = Version(installed_version) if installed_version else None
    except InvalidVersion:
        installed = None
    allow_pre = installed is not None and installed.is_prerelease
    newer = sorted(
        version
        for version in releases
        if (installed is None or version > installed) and (allow_pre or not version.is_prerelease)
    )

    first = None
    inspected: dict[Version, VersionFinding] = {}
    for version in newer[:max_versions]:
        inspected[version] = _inspect(client, version, releases[version])
        if inspected[version].evidence:
            first = inspected[version]
            break

    latest = None
    if newer:
        latest = inspected.get(newer[-1]) or _inspect(client, newer[-1], releases[newer[-1]])
    return Audit(
        index_url=index_url,
        package=package,
        installed=installed_version,
        served_json=served_json,
        has_metadata=any(file.has_metadata for file in files),
        credentials=client.credentials_for(index_url),
        first_with_license=first,
        latest=latest,
        newer_count=len(newer),
        checked=len(inspected),
    )


def format_audit(audit: Audit) -> str:
    """Render an :class:`Audit` for a terminal.

    Args:
        audit: The result to describe.

    Returns:
        Multi-line text: what the index supports, then the finding and what to do about it.
    """
    lines = [
        f"  Index: {redact_url(audit.index_url)}",
        (
            f"    credentials: {audit.credentials}; JSON API: {'yes' if audit.served_json else 'no'}; "
            f"separate metadata (PEP 658): {'yes' if audit.has_metadata else 'no (wheels are downloaded)'}"
        ),
        f"  {audit.package} {audit.installed or '(not installed)'}:",
    ]
    if audit.first_with_license:
        found = audit.first_with_license
        lines.append(f"    {found.version} is the first newer release that ships a license ({found.evidence}).")
        if audit.latest and audit.latest.version != found.version:
            lines.append(f"    The latest release is {audit.latest.version}.")
        lines.append(
            f"    -> upgrading to {audit.package}>={found.version} would let this be detected. Whether your other "
            "dependencies allow that is up to your resolver."
        )
    elif not audit.newer_count:
        lines.append("    This index lists no newer release, so an upgrade isn't available here.")
    else:
        lines.append(
            f"    None of the {audit.checked} newer release(s) checked declares a license, so upgrading "
            "won't help by itself."
        )
        if audit.latest and audit.latest.note:
            lines.append(f"    Latest release ({audit.latest.version}) couldn't be inspected: {audit.latest.note}")
        if audit.checked < audit.newer_count:
            lines.append(f"    ({audit.newer_count - audit.checked} newer release(s) were not checked.)")
    lines.append("    Detected by what the release declares -- a wheel can bundle a license without declaring it.")
    return "\n".join(lines)
