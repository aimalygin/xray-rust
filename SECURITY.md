# Security Policy

`xray-rust` is experimental networking software and has not received an
independent security audit. Only the current `main` branch receives security
fixes; no stable release series is supported yet.

## Reporting a vulnerability

Do not report vulnerabilities, credentials, private keys, production
configuration, or unredacted logs in a public issue.

Use GitHub's private vulnerability reporting page:

https://github.com/aimalygin/xray-rust/security/advisories/new

If private reporting is unavailable, open a public issue containing no
sensitive details and ask the maintainer to establish a private channel.

Include, when applicable:

- the affected commit or version;
- platform and architecture;
- a minimal reproduction using synthetic credentials and endpoints;
- security impact and expected behavior;
- redacted logs or crash output.

If a live credential has already been exposed, revoke or rotate it before
sharing a report. Removing a value from Git history does not invalidate it.

Repository maintainers should keep GitHub secret scanning, push protection,
and private vulnerability reporting enabled. CI also rejects unreviewed
credential-shaped JSON fixtures and known retired live-profile values.

Reports are handled on a best-effort basis until a formal release and support
policy exists. Please allow the maintainer time to reproduce and coordinate a
fix before public disclosure.
