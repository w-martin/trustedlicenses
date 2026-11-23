# Choosing a policy

Most of what a license asks of you depends on what you do with the code: whether it leaves
your organisation and, if it does, whether you hand over copies or only host it. License
categories group licenses by what they say, so they can't know that.

Start from the same base whatever you're building:

```toml
[tool.trustedlicenses]
allowed-categories = ["Permissive", "Public Domain", "Copyleft Limited"]
```

Then accept anything else one package at a time, once you've checked what it asks of you. A
failing package's message prints the line to add, and `l` in the review writes it:

```toml
[tool.trustedlicenses.accepted-licenses]
somepkg = ["GPL-3.0-only"]
```

| A dependency under... | Internal tooling or pipelines | Open-source package or tool | Product |
|---|---|---|---|
| Permissive, Public Domain | Usually fine | Usually fine | Usually fine; keep the notices |
| Copyleft Limited: LGPL, MPL, EPL, CDDL | Usually fine | Usually fine | Usually fine; shipping it has steps |
| Copyleft: GPL | Usually fine | Fits if your project is GPL | Hosted: usually fine. Shipped: avoid |
| Copyleft: AGPL | Fine unless you modify it and it's used over a network | Fits if your project is GPL-3.0 or AGPL | Shipped: avoid. Hosted: avoid if modified |
| Source-available: BUSL, SSPL, Elastic, CC-BY-NC | Read the terms | Avoid | Read the terms |

Not sure, or it may ship later? Use the Product column.

Both copyleft categories also hold licenses that don't follow these rules; see
[Licenses to check individually](#licenses-to-check-individually). This page summarises the
license texts and links the clauses; it isn't legal advice (see the
[legal disclaimer](https://github.com/w-martin/trustedlicenses#legal-disclaimer)).

## Internal tooling or pipelines

Nothing you build leaves your organisation: CI scripts, data pipelines, internal services
and dashboards.

The GPL's conditions start when you give copies to someone else: *"You may make, run and
propagate covered works that you do not convey, without conditions so long as your license
otherwise remains in force"* ([GPLv3 §2](https://spdx.org/licenses/GPL-3.0-only.html)), and
*"The act of running the Program is not restricted"*
([GPLv2 §0](https://spdx.org/licenses/GPL-2.0-only.html)). The MPL's and LGPL's conditions
are also attached to distributing. Three things still need care.

Know where your organisation ends. Giving a tool to a client or partner is distribution. GPLv3 §2
lets you give copies to contractors only so they can modify or run the software exclusively
for you, under your direction and control. The FSF's GPL FAQ covers
[use within one organisation](https://www.gnu.org/licenses/gpl-faq.html#InternalDistribution)
and [subsidiaries](https://www.gnu.org/licenses/gpl-faq.html#DistributeSubsidiary).

AGPL adds a network condition. A modified version must offer its source to *"all users interacting
with it remotely through a computer network"*
([AGPL-3.0 §13](https://spdx.org/licenses/AGPL-3.0-only.html)). Using it unmodified doesn't
trigger this.

Some source-available licenses restrict use itself.
[BUSL-1.1](https://spdx.org/licenses/BUSL-1.1.html) allows *"non-production use"*, plus any
production use its Additional Use Grant permits, until its Change Date.
[CC-BY-NC-4.0](https://spdx.org/licenses/CC-BY-NC-4.0.html) excludes use *"primarily
intended for or directed towards commercial advantage"*. SSPL and Elastic mostly restrict
offering the software to others as a service; see [Product](#product).

## Open-source package or tool

You publish source that other people install, from PyPI or a Git host. Your dependencies
are installed alongside it, under their own licenses.

Whether GPL fits depends on your own license. A GPL dependency fits a GPL project. For a
permissive project (MIT, Apache-2.0, ...), whether importing a GPL module makes your code
part of a combined work is disputed, but anyone who ships your tool bundled with it takes on
the GPL's conditions. Look for an alternative, or accept the package on its own. Declaring
`[project.license]` helps here: the
[compatibility notes](usage.md#a-narrow-fsf-grounded-compatibility-check) then flag the
GPLv2-only and GPLv3 mismatches the FSF documents.

Copyleft Limited is usually fine. MPL-2.0 is copyleft per file: files that contain no MPL
code *"do not need to be distributed under the terms of the MPL"*
([MPL 2.0 FAQ](https://www.mozilla.org/en-US/MPL/2.0/FAQ/), Q11).

Avoid source-available licenses. Your users inherit restrictions you can't waive for them.

## Product

You ship software to customers (installers, container images, appliances, on-premises
deployments) or host it for them.

If you ship copies, each copyleft license asks something different:

- For MPL-2.0, make the MPL-licensed source available and tell recipients how to get it. Your
  license for the executable can't limit their rights to that source
  ([MPL-2.0 §3.2](https://www.mozilla.org/en-US/MPL/2.0/)). Your own files can stay under
  your own terms (§3.3).
- For LGPL-3.0, your terms must not restrict modifying the library, or reverse engineering to
  debug such changes. You must also say the library is used, ship the GPL and LGPL texts,
  include its copyright notice wherever you display notices, let users run your product with
  a modified version of the library (for example through a shared library already on their
  system), and provide installation information where GPLv3 §6 would require it
  ([LGPL-3.0 §4](https://spdx.org/licenses/LGPL-3.0-only.html)). LGPL-2.1 differs.
- For GPL and AGPL, shipping copies applies their full terms, even unmodified, which is why
  `"Copyleft"` stays out of the base.

If you only host it, the GPL asks nothing of you at distribution time: *"Mere interaction
with a user through a computer network, with no transfer of a copy, is not conveying"*
([GPLv3 §0](https://spdx.org/licenses/GPL-3.0-only.html)). AGPL §13 still applies if you
modify the package.

Source-available licenses often target hosting.
[Elastic-2.0](https://spdx.org/licenses/Elastic-2.0.html) forbids providing the software
*"to third parties as a hosted or managed service"* that exposes a substantial set of its
features, and forbids circumventing its license keys in any use.
[SSPL-1.0](https://spdx.org/licenses/SSPL-1.0.html) lets you run it internally (§2), but
offering it to third parties as a service requires publishing your "Service Source Code"
(§13). BUSL-1.1 limits production use.

## Tightening for publishing

Before you publish or ship, `trustedlicenses pin` swaps `allowed-categories` for
`allowed-licenses`, the specific licenses your project uses today
([Pinning to specific licenses](usage.md#pinning-to-specific-licenses)). Nothing that passes
now starts failing, but a license new to the project fails until someone accepts it,
including one from the list below that shares a category with something you already allow.

To show a reviewer what the policy accepts and why, run `trustedlicenses report`
([A report for review](usage.md#a-report-for-review)).

## Licenses to check individually

The categories, which come from ScanCode Toolkit ([Categories](usage.md#categories)), are
coarse. These licenses sit in the categories above but don't behave like the rest. The list
isn't exhaustive.

| License | Category | Why |
|---|---|---|
| [RPL-1.5](https://spdx.org/licenses/RPL-1.5.html) | Copyleft Limited | "Deploy" includes *"any and all internal use or distribution of Licensed Software within Your business or organization other than for Research and/or Personal Use"* (§1.2) |
| [APSL-2.0](https://spdx.org/licenses/APSL-2.0.html) | Copyleft Limited | "Externally Deploy" includes providing a service to others (§1.4); modified code deployed that way must be released as source (§2.2) |
| [RPSL-1.0](https://spdx.org/licenses/RPSL-1.0.html) | Copyleft Limited | Covers code *"used to provide any services to anyone other than You"* (§1.7); such derivative works must be licensed as a whole under the RPSL (§4.1) |
| [EUPL-1.2](https://spdx.org/licenses/EUPL-1.2.html) | Copyleft Limited | Its conditions cover "Communication" of the work as well as distribution; whether that reaches hosted services is disputed |
| [QPL-1.0](https://spdx.org/licenses/QPL-1.0.html) | Copyleft Limited | Software that links with it must, when distributed, come with its full source and the right to redistribute it (§6) |
| [CeCILL-2.1](https://spdx.org/licenses/CECILL-2.1.html) | Copyleft Limited | Modules that run in the same address space count as contributions |
| [CC-BY-SA-4.0](https://spdx.org/licenses/CC-BY-SA-4.0.html) | Copyleft Limited | A content license with no notion of linking; share-alike applies to adaptations you share (§3(b)) |
| [Parity-7.0.0](https://spdx.org/licenses/Parity-7.0.0.html) | Copyleft | *"Contribute software you develop, operate, or analyze with this software"*: triggered by use |
| [OSL-3.0](https://spdx.org/licenses/OSL-3.0.html), [CPAL-1.0](https://spdx.org/licenses/CPAL-1.0.html) | Copyleft | "External Deployment", including use over a network by anyone other than you, counts like distribution (OSL-3.0 §5) |

## Changing your case later

The setup saves your answer as `use-case`, which never affects pass/fail. Every case starts
from the same base, so switching means editing `use-case` and revisiting the packages under
`accepted-licenses`.
