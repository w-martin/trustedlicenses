"""Tests for trustedlicenses.index -- fake client for logic, a real local HTTP server for the wire."""

from __future__ import annotations

import http
import io
import json
import ssl
import threading
import urllib.error
import urllib.request
import zipfile
from http.client import HTTPMessage
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import TYPE_CHECKING

import pytest

from trustedlicenses.index import (
    HttpClient,
    IndexHttpError,
    IndexQueryError,
    Response,
    _DropAuthOnCrossHostRedirect,
    _http_message,
    _network_message,
    audit_package,
    format_audit,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from trustedlicenses.index import Audit, VersionFinding

JSON_TYPE = "application/vnd.pypi.simple.v1+json"
HTML_TYPE = "text/html"
WITH_LICENSE = "Metadata-Version: 2.5\nName: pkg\nVersion: {v}\nLicense-File: LICENSE\n"
WITHOUT_LICENSE = (
    "Metadata-Version: 2.0\nName: pkg\nVersion: {v}\nLicense: BSD\nClassifier: License :: OSI Approved :: BSD License\n"
)


def make_wheel(version: str, *, license_file: bool, declare: bool = True) -> bytes:
    """A minimal real wheel; ``declare`` controls whether METADATA carries License-File."""
    buffer = io.BytesIO()
    metadata = (WITH_LICENSE if (license_file and declare) else WITHOUT_LICENSE).format(v=version)
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(f"pkg-{version}.dist-info/METADATA", metadata)
        if license_file:
            archive.writestr(f"pkg-{version}.dist-info/licenses/LICENSE", "text")
    return buffer.getvalue()


def _found(audit: Audit) -> VersionFinding:
    assert audit.first_with_license is not None
    return audit.first_with_license


def _latest(audit: Audit) -> VersionFinding:
    assert audit.latest is not None
    return audit.latest


class FakeClient:
    """Serves a JSON project page and per-version metadata, recording what was fetched."""

    def __init__(
        self,
        versions: dict[str, str],
        *,
        sdist_only: tuple[str, ...] = (),
        yanked: tuple[str, ...] = (),
        extra_filenames: tuple[str, ...] = (),
    ) -> None:
        self.versions = versions
        self.sdist_only = sdist_only
        self.yanked = yanked
        self.extra_filenames = extra_filenames
        self.fetched: list[str] = []

    def credentials_for(self, url: str) -> str:  # noqa: ARG002
        return "none"

    def get(self, url: str, *, accept: str | None = None, max_bytes: int | None = None) -> Response:  # noqa: ARG002
        self.fetched.append(url)
        if url.endswith("/pkg/"):
            files: list[dict[str, str | bool]] = [
                {"filename": name, "url": f"https://idx/files/{name}"} for name in self.extra_filenames
            ]
            for version in self.versions:
                name = f"pkg-{version}.tar.gz" if version in self.sdist_only else f"pkg-{version}-py3-none-any.whl"
                files.append(
                    {
                        "filename": name,
                        "url": f"https://idx/files/{name}",
                        "core-metadata": True,
                        "yanked": version in self.yanked,
                    }
                )
            return Response(url, JSON_TYPE, json.dumps({"files": files}).encode())
        version = url.rsplit("pkg-", 1)[1].split("-py3", maxsplit=1)[0]
        return Response(url, "text/plain", self.versions[version].encode())


def _audit(versions: dict[str, str], installed: str, sdist_only: tuple[str, ...] = ()) -> tuple[Audit, FakeClient]:
    client = FakeClient(versions, sdist_only=sdist_only)
    return audit_package(client, "https://idx/simple", "pkg", installed), client


def test_finds_the_first_newer_release_that_ships_a_license() -> None:
    """The webencodings shape: 0.5.1 has none, 0.6.0 and 0.6.1 do."""
    audit, _ = _audit(
        {
            "0.5.1": WITHOUT_LICENSE.format(v="0.5.1"),
            "0.6.0": WITH_LICENSE.format(v="0.6.0"),
            "0.6.1": WITH_LICENSE.format(v="0.6.1"),
        },
        "0.5.1",
    )

    assert str(_found(audit).version) == "0.6.0"
    assert _found(audit).evidence == "License-File: LICENSE"
    assert str(_latest(audit).version) == "0.6.1"
    assert audit.served_json
    assert audit.has_metadata
    rendered = format_audit(audit)
    assert "0.6.0 is the first newer release" in rendered
    assert "The latest release is 0.6.1" in rendered


def test_only_newer_releases_are_considered() -> None:
    """A licensed release *older* than the installed one is no help."""
    audit, client = _audit({"0.4": WITH_LICENSE.format(v="0.4"), "0.5.1": WITHOUT_LICENSE.format(v="0.5.1")}, "0.5.1")

    assert audit.first_with_license is None
    assert audit.newer_count == 0
    assert not any("0.4" in url for url in client.fetched)
    assert "no newer release, so an upgrade isn't available" in format_audit(audit)


def test_an_unparseable_installed_version_still_considers_every_release() -> None:
    """A non-PEP-440 installed-version string (legacy/odd packaging) doesn't crash the audit."""
    audit, _ = _audit({"1.0": WITH_LICENSE.format(v="1.0")}, "not-a-real-version")

    assert str(_found(audit).version) == "1.0"


def test_yanked_releases_are_skipped_in_the_json_index() -> None:
    """A yanked release is never offered as the fix."""
    client = FakeClient({"1.0": WITHOUT_LICENSE.format(v="1.0"), "1.1": WITH_LICENSE.format(v="1.1")}, yanked=("1.1",))

    audit = audit_package(client, "https://idx/simple", "pkg", "1.0")

    assert audit.first_with_license is None
    assert audit.newer_count == 0


def test_unparseable_filenames_on_the_index_are_skipped() -> None:
    """A listed file that isn't a wheel or sdist filename (e.g. a stray .egg) doesn't crash the audit."""
    client = FakeClient({"1.0": WITH_LICENSE.format(v="1.0")}, extra_filenames=("pkg-nonsense.egg",))

    audit = audit_package(client, "https://idx/simple", "pkg", "0.9")

    assert str(_found(audit).version) == "1.0"


def test_reports_when_no_newer_release_declares_a_license() -> None:
    """Upgrading won't help if nothing newer declares one."""
    audit, _ = _audit({"1.0": WITHOUT_LICENSE.format(v="1.0"), "1.1": WITHOUT_LICENSE.format(v="1.1")}, "1.0")

    assert audit.first_with_license is None
    assert audit.checked == 1
    assert "won't help" in format_audit(audit)


def test_prereleases_are_skipped_unless_installed_one_is_a_prerelease() -> None:
    """Don't recommend an upgrade to a release candidate."""
    versions: dict[str, str] = {"1.0": WITHOUT_LICENSE.format(v="1.0"), "1.1rc1": WITH_LICENSE.format(v="1.1rc1")}

    stable, _ = _audit(versions, "1.0")
    pre, _ = _audit(versions, "1.0rc1")

    assert stable.first_with_license is None
    assert str(_found(pre).version) == "1.1rc1"


def test_sdist_only_release_is_reported_not_guessed() -> None:
    """A release with no wheel can't be inspected cheaply -- say so instead of pretending."""
    audit, _ = _audit({"1.0": WITHOUT_LICENSE.format(v="1.0"), "1.1": ""}, "1.0", ("1.1",))

    assert audit.first_with_license is None
    assert "source distribution" in str(_latest(audit).note)
    assert "couldn't be inspected" in format_audit(audit)


def test_window_is_bounded_but_latest_is_still_checked() -> None:
    """Only max_versions releases are walked; the latest is inspected regardless."""
    versions: dict[str, str] = {f"1.{i}": WITHOUT_LICENSE.format(v=f"1.{i}") for i in range(6)}
    client = FakeClient(versions)

    max_checked, total_newer = 2, 5
    audit = audit_package(client, "https://idx/simple", "pkg", "1.0", max_versions=max_checked)

    assert audit.checked == max_checked
    assert audit.newer_count == total_newer
    assert str(_latest(audit).version) == "1.5"
    assert "not checked" in format_audit(audit)


def test_no_installed_version_considers_every_release() -> None:
    """Unknown installed version -> audit from the beginning."""
    audit, _ = _audit({"1.0": WITH_LICENSE.format(v="1.0")}, "")

    assert str(_found(audit).version) == "1.0"


def test_a_declared_resolvable_license_counts_even_without_a_license_file() -> None:
    """License-Expression = MIT is enough for the tool to detect it."""
    audit, _ = _audit({"1.0": "Metadata-Version: 2.4\nName: pkg\nVersion: 1.0\nLicense-Expression: MIT\n"}, "")

    assert _found(audit).evidence == "declares MIT"


# ---------------------------------------------------------------------------
# The wire: a real local HTTP server.
# ---------------------------------------------------------------------------


class _Site:
    """Configurable fake index. Records the Authorization header of each request."""

    def __init__(self) -> None:
        self.wheels: dict[str, bytes] = {}
        self.require_auth: str | None = None
        self.seen_auth: list[str | None] = []
        self.redirect_files_to: str | None = None
        self.advertise_metadata = False
        self.json = False
        self.port = 0
        self.yanked_html_files: set[str] = set()


@pytest.fixture
def site() -> Iterator[_Site]:  # noqa: C901
    """A running local index; tests configure its ``_Site`` state."""
    state = _Site()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:  # noqa: A002, ARG002
            return

        def do_GET(self) -> None:
            state.seen_auth.append(self.headers.get("Authorization"))
            if state.require_auth and self.headers.get("Authorization") != state.require_auth:
                self.send_response(401)
                self.end_headers()
                return
            if self.path == "/simple/pkg/":
                self._project_page()
            elif self.path.startswith("/files/") and state.redirect_files_to:
                self.send_response(302)
                self.send_header("Location", state.redirect_files_to + self.path)
                self.end_headers()
            elif self.path.startswith("/files/"):
                self._send(state.wheels.get(self.path.rsplit("/", 1)[-1]), "application/octet-stream")
            else:
                self.send_response(404)
                self.end_headers()

        def _project_page(self) -> None:
            if state.json:
                files = [{"filename": n, "url": f"/files/{n}"} for n in state.wheels]
                self._send(json.dumps({"files": files}).encode(), JSON_TYPE)
                return
            links = "".join(self._link(name) for name in state.wheels)
            self._send(f"<html><body>{links}</body></html>".encode(), HTML_TYPE)

        @staticmethod
        def _link(name: str) -> str:
            yanked = ' data-yanked=""' if name in state.yanked_html_files else ""
            return f'<a href="../../files/{name}#sha256=x"{yanked}>{name}</a><br>'

        def _send(self, body: bytes | None, content_type: str) -> None:
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    state.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield state
    server.shutdown()
    server.server_close()


def _url(site: _Site, userinfo: str = "") -> str:
    return f"http://{userinfo}127.0.0.1:{site.port}/simple"


def test_yanked_releases_are_skipped_in_an_html_index(site: _Site) -> None:
    """PEP 503's data-yanked attribute is honoured the same way PEP 691's yanked field is."""
    site.wheels = {"pkg-1.1-py3-none-any.whl": make_wheel("1.1", license_file=True)}
    site.yanked_html_files = {"pkg-1.1-py3-none-any.whl"}

    audit = audit_package(HttpClient(), _url(site), "pkg", "1.0")

    assert audit.first_with_license is None
    assert audit.newer_count == 0


def test_html_only_index_without_pep_658_downloads_the_wheel_to_inspect_it(site: _Site) -> None:
    """The fallback path a plain Nexus-style index needs: PEP 503 HTML, no separate metadata."""
    site.wheels = {
        "pkg-0.5.1-py3-none-any.whl": make_wheel("0.5.1", license_file=False),
        "pkg-0.6.0-py3-none-any.whl": make_wheel("0.6.0", license_file=True),
    }

    audit = audit_package(HttpClient(), _url(site), "pkg", "0.5.1")

    assert not audit.served_json
    assert not audit.has_metadata
    assert str(_found(audit).version) == "0.6.0"
    assert "License-File" in str(_found(audit).evidence)
    assert "wheels are downloaded" in format_audit(audit)


def test_a_wheel_bundling_a_license_without_declaring_it_is_still_seen(site: _Site) -> None:
    """Older wheels: no License-File header, but the file is in the archive."""
    site.wheels = {"pkg-0.6.0-py3-none-any.whl": make_wheel("0.6.0", license_file=True, declare=False)}

    audit = audit_package(HttpClient(), _url(site), "pkg", "0.5.1")

    assert _found(audit).evidence == "bundles LICENSE"


def test_json_index_is_used_when_offered(site: _Site) -> None:
    """PEP 691 responses are parsed and relative URLs resolved."""
    site.json = True
    site.wheels = {"pkg-0.6.0-py3-none-any.whl": make_wheel("0.6.0", license_file=True)}

    audit = audit_package(HttpClient(), _url(site), "pkg", "0.5.1")

    assert audit.served_json
    assert audit.first_with_license is not None


def test_credentials_in_the_url_are_sent_and_never_shown(site: _Site) -> None:
    """user:pass@ becomes a Basic header; the report says where they came from, not what they are."""
    site.require_auth = "Basic " + "dXNlcjpzM2NyZXQ="  # user:s3cret
    site.wheels = {"pkg-0.6.0-py3-none-any.whl": make_wheel("0.6.0", license_file=True)}
    url = _url(site, "user:s3cret@")

    audit = audit_package(HttpClient(), url, "pkg", "0.5.1")

    assert audit.credentials == "in the index URL"
    assert "s3cret" not in format_audit(audit)
    assert audit.first_with_license is not None


def test_credentials_from_netrc(site: _Site, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """.netrc (via NETRC) supplies credentials when the URL has none."""
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login user password s3cret\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    site.require_auth = "Basic dXNlcjpzM2NyZXQ="
    site.wheels = {"pkg-0.6.0-py3-none-any.whl": make_wheel("0.6.0", license_file=True)}

    audit = audit_package(HttpClient(), _url(site), "pkg", "0.5.1")

    assert audit.credentials == ".netrc"
    assert audit.first_with_license is not None


def test_rejected_credentials_explain_where_they_come_from(site: _Site) -> None:
    """A 401 says credentials are environmental -- it doesn't just dump an HTTP error."""
    site.require_auth = "Basic never-matches"

    with pytest.raises(IndexHttpError, match=r"\.netrc") as error:
        audit_package(HttpClient(), _url(site), "pkg", "0.5.1")

    assert error.value.status == http.HTTPStatus.UNAUTHORIZED


def test_unknown_package_says_it_is_not_on_this_index(site: _Site) -> None:
    """404 -> 'likely internal', the normal answer for an unpublished package."""
    with pytest.raises(IndexHttpError, match="not found on this index"):
        HttpClient().get(_url(site) + "/nope/")


def test_a_generic_http_error_status_is_reported_plainly() -> None:
    """A status with no special-cased explanation still says what happened."""
    assert "HTTP 500" in _http_message(500, "https://idx/pkg/")


def test_tls_error_message_points_at_ssl_cert_file() -> None:
    """A TLS failure names the environment variable that fixes a private-CA index."""
    error = urllib.error.URLError(ssl.SSLError("certificate verify failed"))

    assert "SSL_CERT_FILE" in _network_message(error, "https://idx/pkg/")


def test_non_tls_network_error_does_not_mention_ssl_cert_file() -> None:
    """A plain connection failure isn't mistaken for a certificate problem."""
    error = urllib.error.URLError(OSError("connection refused"))

    message = _network_message(error, "https://idx/pkg/")
    assert "SSL_CERT_FILE" not in message
    assert "Could not reach" in message


def test_request_that_times_out_is_an_explained_error(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    """A hung server is reported with the configured timeout, not left to raise raw."""

    def raise_timeout(*_args: object, **_kwargs: object) -> None:
        raise TimeoutError

    client = HttpClient()
    monkeypatch.setattr(client._opener, "open", raise_timeout)

    with pytest.raises(IndexQueryError, match="Timed out after"):
        client.get(_url(site) + "/pkg/")


def test_credentials_are_dropped_when_redirected_to_another_host() -> None:
    """Auth must not follow a redirect off-host, but is kept for same-host redirects."""
    handler = _DropAuthOnCrossHostRedirect()
    request = urllib.request.Request("http://a.example/x", headers={"Authorization": "Basic abc"})

    cross = handler.redirect_request(request, io.BytesIO(), 302, "Found", HTTPMessage(), "http://b.example/y")
    same = handler.redirect_request(request, io.BytesIO(), 302, "Found", HTTPMessage(), "http://a.example/z")

    assert cross is not None
    assert same is not None
    assert not cross.has_header("Authorization")
    assert same.has_header("Authorization")


def test_oversized_wheel_is_not_downloaded(site: _Site, monkeypatch: pytest.MonkeyPatch) -> None:
    """The download fallback is size-capped; a too-large wheel is reported, not fetched whole."""
    monkeypatch.setattr("trustedlicenses.index.MAX_WHEEL_BYTES", 50)
    site.wheels = {"pkg-0.6.0-py3-none-any.whl": make_wheel("0.6.0", license_file=True)}

    audit = audit_package(HttpClient(), _url(site), "pkg", "0.5.1")

    assert audit.first_with_license is None
    assert "larger than" in str(_latest(audit).note)


def test_unreachable_index_is_an_explained_error() -> None:
    """Connection refused becomes a message, not a traceback."""
    with pytest.raises(IndexQueryError, match="Could not reach"):
        HttpClient().get("http://127.0.0.1:1/simple/pkg/")


def test_non_http_urls_are_refused() -> None:
    """file:// and friends are never fetched."""
    with pytest.raises(IndexQueryError, match="non-http"):
        HttpClient().get("file:///etc/passwd")
