# Security Policy

Only the current `main` branch receives security fixes. The project has not
received an independent security audit.

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

Please allow the maintainer time to reproduce the report and coordinate a fix
before public disclosure.

## Disclosed: pre-release live profile in repository history

Before this repository was prepared for open source release, a real VLESS +
REALITY *client* profile was committed as a test fixture and used as input to
log-redaction unit tests. It was scrubbed from the tree in `755a3a4`
(2026-07-27) and replaced with RFC documentation placeholders, but it remains
reachable in the pre-release history and was present in the default branch of
the public repository before that date.

The disclosed values are the profile's server address, camouflage `serverName`
(SNI), VLESS user id, REALITY `publicKey`, and REALITY `shortId`. **The
profile has been revoked server-side.** Note that in REALITY the client's
`publicKey` is a shared value distributed only to authorized clients, not a
publishable public key: together with a valid `shortId` it lets a third party
forge the client-side REALITY authenticator, which defeats the protocol's
resistance to active probing. Revocation, not removal from history, is what
withdraws that capability.

The REALITY server private key was never committed. Every `privateKey` and
`secretKey` literal in the repository's history is either a placeholder
constant or a template token substituted at test runtime with a locally
generated ephemeral key, and none derives to the disclosed `publicKey`. Passive
decryption of captured traffic and impersonation of the server were therefore
never possible from repository contents alone.

The history is deliberately **not** rewritten. The values were public before
they were scrubbed, so rewriting would not withdraw them: unreferenced objects
stay retrievable by SHA, pull-request refs survive a force push, published
push events are archived by third parties, and any clone taken during the
window retains everything. Rewriting would in exchange invalidate every
published commit SHA, including those cited in benchmark charts and
documentation. `scripts/tests/check-json-fixture-safety.py` therefore
grandfathers the two pre-release commits that carry these values, by commit
identity rather than by date, and still fails on any other commit — including
any new one — that reintroduces them.

The digest allowlist in that script covers only the user id, `publicKey`, and
`shortId`. The server address and SNI are deliberately absent: an unsalted
digest of an IPv4 address or a domain name is recoverable by exhaustive search,
so listing them would republish what the list exists to withhold. Those two
values cannot be rotated in place and are treated as disclosed.
