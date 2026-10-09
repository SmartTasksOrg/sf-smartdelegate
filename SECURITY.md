# Security policy

SmartDelegate 0.3.0 is experimental software. It has had no independent
security review. [README "Status"](README.md#status) says what is tested and
what is not.

## Supported versions

| Version | Security fixes |
|---|---|
| 0.3.x | yes |
| older | no; upgrade |

## Reporting a vulnerability

Report privately through GitHub: open
<https://github.com/SmartTasksOrg/sf-smartdelegate>, go to the **Security** tab and
choose **Report a vulnerability** (GitHub private vulnerability reporting).
Only the maintainers can read the report.

Do not open a public issue, pull request or discussion for a vulnerability,
and do not put a working exploit in one.

If the Security tab shows no "Report a vulnerability" button, private
reporting is switched off. Open a public issue that says only "I have a
security report; please enable private vulnerability reporting", with no
details, and wait for a maintainer.

## What to include

- The version (`sf-smartdelegate --version`) and your platform.
- The smallest input that shows the problem, and what you expected.
- Whether you checked other versions or ports.

Remove real secrets, tokens and personal data from what you send.

## Packages that pretend to be SmartDelegate

The only package names the maintainers publish are listed with
`"registered": true` in [names.json](names.json). Official releases are built
by `.github/workflows/release.yml` in `SmartTasksOrg/sf-smartdelegate` and published
with trusted publishing, so each file carries a provenance attestation that
names this repository and that workflow.

A package on any registry that uses this project's name but is not listed
there, or a release file without that provenance, is not ours. Report it
through the private form above, and to the registry (PyPI: "Report project
as malware" on the project page; npm: "Report malware" on the package page;
crates.io: help@crates.io).

## What to expect

- An answer in the private report. No response time is promised; this is a
  small project without a security team on call.
- A confirmed issue is fixed in a new release, announced in `CHANGELOG.md`
  and in a GitHub security advisory, with credit to the reporter unless they
  ask not to be named.
- There is no bug bounty.

## Scope

In scope: the code in this repository and its build and release files.
Especially: anything that lets an agent act with more than the role it was lent (a token, a sub-agent token, an approval or a proxy route granting more than the policy allows), a cross-tenant read, a field that should be masked reaching the agent, or an audit chain that verifies after tampering.
Out of scope: the demo data under `demo/` and the static pages under `site/`.
