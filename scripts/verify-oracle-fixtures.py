#!/usr/bin/env python3
"""Regenerate every Go-oracle fixture and compare it with the committed copy.

The fixtures under `tests/fixtures/reality`, `tests/fixtures/masquerade` and
`tests/fixtures/grpc` are the only thing pinning xray-rust's ClientHello,
masquerade-header and gRPC wire shaping to the Go reference implementation.
Nothing else in CI runs the oracles, so a fixture can drift away from what its
oracle now produces -- after a `go get`, a Go toolchain change, or an Xray-core
resync -- without a single test turning red.

Every oracle already supports `-check <fixture>`: it regenerates its artefact
from the flags it is given and compares the result byte for byte. The flags
therefore have to be the ones the fixture was generated with, or the comparison
is against a different artefact and its verdict means nothing.

Rather than keep a fixture-to-flags table, which goes stale the moment someone
adds a fixture, each oracle below declares two functions:

  * `claims`, a predicate over the parsed fixture that recognises the oracle's
    own output shape, and
  * `flags`, which reads the generation parameters back out of that same
    output -- the shape fixtures record `fingerprint`, `server_name` and
    `websocket_alpn`, the masquerade ones record `variant` and `user_agent`,
    the gRPC ones record `wire`.

A new fixture is therefore covered automatically as long as an oracle
recognises it, and a fixture no oracle recognises is a hard failure rather than
a silent skip. The mirror hole is closed too: an oracle that ends up claiming
nothing fails the run, so deleting the last fixture of a family cannot quietly
retire its oracle.

Usage:

    scripts/verify-oracle-fixtures.sh [fixture ...]

With no arguments every fixture is checked. Paths narrow the run to a subset,
which is only a convenience for iterating locally.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = REPOSITORY_ROOT / "tests" / "fixtures"

# The directories whose JSON is Go-oracle output. `tests/fixtures/configs` is
# deliberately absent: it holds Rust configuration fixtures that no oracle
# generates.
FIXTURE_DIRECTORIES = (
    FIXTURE_ROOT / "reality",
    FIXTURE_ROOT / "masquerade",
    FIXTURE_ROOT / "grpc",
)

MASQUERADE_MODULE = "tools/reality-oracle/masquerade"
GRPC_MODULE = "tools/reality-oracle/grpc"

# The browsers a masquerade header block draws a version for, in the order the
# fixture's `versions` object lists them.
BROWSERS = ("chrome", "firefox", "safari", "curl")

# The one header whose value cannot be restated in the oracle's version
# numbers, and so the only one allowed the weaker verdict in
# `classify_version_drift`. Every other value -- `User-Agent` included -- prints
# its version rather than being seeded by it, so substitution reproduces it
# exactly and a mismatch there is a real regression.
CHROME_SEEDED_HEADER = "Sec-CH-UA"


def root_oracle(entry: str, tag: str | None = None) -> tuple[str, ...]:
    """Build the `go run` invocation for an oracle in the root module."""
    command = ["go", "run"]
    if tag is not None:
        command += ["-tags", tag]
    command.append(entry)
    return tuple(command)


def masquerade_oracle(tag: str) -> tuple[str, ...]:
    """Build the `go run` invocation for an oracle in the masquerade module.

    Those oracles live in a module of their own because importing Xray-core
    raises `golang.org/x/crypto` to a version whose uTLS emits different
    ClientHello bytes; see the header of
    `tools/reality-oracle/masquerade/go.mod`. `-C` moves the Go command into
    that module without moving this process, so fixture paths stay resolvable
    from the repository root.
    """
    return ("go", "run", "-C", MASQUERADE_MODULE, "-tags", tag, ".")


def grpc_oracle(tag: str) -> tuple[str, ...]:
    """Build the `go run` invocation for an oracle in the gRPC module.

    A third module for the reason there is a second one, twice over: this
    oracle imports `google.golang.org/grpc`, which raises the root module's
    `golang.org/x/crypto` from v0.36.0 to v0.48.0 on its own, and Xray-core,
    which raises it to v0.50.0 -- and uTLS built against a different
    `x/crypto` emits different ClientHello bytes. See the header of
    `tools/reality-oracle/grpc/go.mod`.
    """
    return ("go", "run", "-C", GRPC_MODULE, "-tags", tag, ".")


def claims_raw_clienthello(document: Any) -> bool:
    return isinstance(document, dict) and "raw_client_hello_hex" in document


def claims_clienthello_raw(document: Any) -> bool:
    # `client_hello_hex`, not the `raw_client_hello_hex` that
    # `claims_raw_clienthello` above looks for: two oracles emit a whole
    # ClientHello, and the key is the only thing telling their output apart.
    return isinstance(document, dict) and "client_hello_hex" in document


def claims_clienthello_shape(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and "utls_id" in document
        and "extension_order" in document
    )


def claims_session_id_vectors(document: Any) -> bool:
    return (
        isinstance(document, list)
        and len(document) > 0
        and all(
            isinstance(vector, dict) and "expected_session_id_hex" in vector
            for vector in document
        )
    )


def claims_masquerade_headers(document: Any) -> bool:
    return (
        isinstance(document, dict) and "variant" in document and "headers" in document
    )


def claims_version_distribution(document: Any) -> bool:
    return (
        isinstance(document, dict) and "installs" in document and "chrome" in document
    )


def claims_grpc_wire(artefact: str) -> Callable[[Any], bool]:
    """Recognise one of the gRPC oracle's artefacts by its own `wire` key.

    Keyed on `wire` rather than on the shape of the payload, because the
    payload shapes collide with oracles already here. The header artefact
    carries a `headers` array, and `claims_masquerade_headers` fires on
    `"variant" in document and "headers" in document` -- so a gRPC fixture that
    grew a `variant` key would be claimed twice and fail as ambiguous. `wire`
    is read by no other oracle, and it doubles as the flag the artefact was
    generated with; see `grpc_wire_flags`.
    """

    def claims(document: Any) -> bool:
        return isinstance(document, dict) and document.get("wire") == artefact

    return claims


def no_flags(document: Any) -> list[str]:
    """For oracles whose output records no generation parameters."""
    del document
    return []


def clienthello_shape_flags(document: Any) -> list[str]:
    """Read `clienthello_shape.go`'s own flags back out of its output.

    `-check` regenerates the shape from these, so a fixture checked with the
    wrong ones reports a mismatch that means nothing. `websocket_alpn` carries
    `omitempty`, so its absence is the `false` the oracle defaults to.
    """
    flags = [
        "-fingerprint",
        require_string(document, "fingerprint"),
        "-server-name",
        require_string(document, "server_name"),
    ]
    if document.get("websocket_alpn"):
        flags.append("-websocket-alpn")
    return flags


def clienthello_raw_flags(document: Any) -> list[str]:
    """Same binary and same flags as the shape mode, plus `-raw`."""
    return [*clienthello_shape_flags(document), "-raw"]


def masquerade_headers_flags(document: Any) -> list[str]:
    """Read `masquerade_headers.go`'s own flags back out of its output."""
    return [
        "-variant",
        require_string(document, "variant"),
        "-user-agent",
        require_string(document, "user_agent"),
    ]


def grpc_wire_flags(document: Any) -> list[str]:
    """Read `grpc_wire.go`'s one flag back out of its output.

    `-wire` selects the artefact -- which of the shared capture's four views is
    printed, or the separate capture `user_agent_validity` runs. Reading it back
    off the fixture rather than hard-coding it per oracle keeps the pairing
    honest: a fixture renamed or re-keyed by hand is checked against the
    artefact it says it is.
    """
    return ["-wire", require_string(document, "wire")]


def require_string(document: Any, key: str) -> str:
    value = document.get(key)
    if not isinstance(value, str):
        raise ValueError(f"expected a string under {key!r}, found {value!r}")
    return value


@dataclass(frozen=True)
class Oracle:
    name: str
    command: tuple[str, ...]
    claims: Callable[[Any], bool]
    flags: Callable[[Any], list[str]]
    # Set only by the masquerade header oracle; see `classify_version_drift`.
    tolerates_version_drift: bool = False


ORACLES: tuple[Oracle, ...] = (
    Oracle(
        name="clienthello",
        command=root_oracle(
            "./tools/reality-oracle/clienthello_fixture.go",
            tag="reality_oracle_clienthello",
        ),
        claims=claims_raw_clienthello,
        flags=no_flags,
    ),
    Oracle(
        name="clienthello-shape",
        command=root_oracle(
            "./tools/reality-oracle/clienthello_shape.go",
            tag="reality_oracle_clienthello_shape",
        ),
        claims=claims_clienthello_shape,
        flags=clienthello_shape_flags,
    ),
    Oracle(
        name="clienthello-raw",
        command=root_oracle(
            "./tools/reality-oracle/clienthello_shape.go",
            tag="reality_oracle_clienthello_shape",
        ),
        claims=claims_clienthello_raw,
        flags=clienthello_raw_flags,
    ),
    Oracle(
        name="session-id-vectors",
        command=root_oracle("./tools/reality-oracle/session_id_vectors.go"),
        claims=claims_session_id_vectors,
        flags=no_flags,
    ),
    Oracle(
        name="masquerade-headers",
        command=masquerade_oracle("reality_oracle_masquerade_headers"),
        claims=claims_masquerade_headers,
        flags=masquerade_headers_flags,
        tolerates_version_drift=True,
    ),
    Oracle(
        name="version-distribution",
        command=masquerade_oracle("reality_oracle_version_distribution"),
        claims=claims_version_distribution,
        flags=no_flags,
    ),
    # Five oracles over one program. Four of them share a capture: the dial
    # that produces a connection preamble is the dial that produces the HEADERS
    # block and the framed Hunks of both calls on it, and splitting it into
    # four programs would be four transcriptions of one dial. The fifth,
    # `grpc-user-agent-validity`, is a dial per case rather than a view of one,
    # so it captures separately -- but it is the same program and the same
    # build tag, so `-wire` still picks which artefact is printed.
    Oracle(
        name="grpc-connection-preamble",
        command=grpc_oracle("reality_oracle_grpc_wire"),
        claims=claims_grpc_wire("connection_preamble"),
        flags=grpc_wire_flags,
    ),
    Oracle(
        name="grpc-request-headers",
        command=grpc_oracle("reality_oracle_grpc_wire"),
        claims=claims_grpc_wire("request_headers"),
        flags=grpc_wire_flags,
    ),
    Oracle(
        name="grpc-hunk-framing",
        command=grpc_oracle("reality_oracle_grpc_wire"),
        claims=claims_grpc_wire("hunk_framing"),
        flags=grpc_wire_flags,
    ),
    Oracle(
        name="grpc-multi-hunk-framing",
        command=grpc_oracle("reality_oracle_grpc_wire"),
        claims=claims_grpc_wire("multi_hunk_framing"),
        flags=grpc_wire_flags,
    ),
    Oracle(
        name="grpc-user-agent-validity",
        command=grpc_oracle("reality_oracle_grpc_wire"),
        claims=claims_grpc_wire("user_agent_validity"),
        flags=grpc_wire_flags,
    ),
)


@dataclass
class Outcome:
    """One fixture's verdict: matched, matched apart from the draw, or failed."""

    fixture: Path
    # Shown only when the fixture fails: the invocation plus what went wrong.
    detail: str
    failed: bool = False
    drifted: bool = False
    # Shown on the fixture's own line: which browser versions the draw moved.
    note: str = ""
    unverified: tuple[str, ...] = ()

    @property
    def status(self) -> str:
        if self.failed:
            return "FAIL"
        return "drift" if self.drifted else "ok"


def discover_fixtures() -> list[Path]:
    fixtures: list[Path] = []
    for directory in FIXTURE_DIRECTORIES:
        if not directory.is_dir():
            raise SystemExit(f"missing fixture directory: {directory}")
        fixtures.extend(sorted(directory.rglob("*.json")))
    return fixtures


def run_oracle(
    oracle: Oracle, arguments: list[str]
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*oracle.command, *arguments],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


def version_tokens(versions: Any) -> list[str]:
    """The four browser version strings a masquerade header block is built on."""
    if not isinstance(versions, dict):
        raise ValueError(f"expected a versions object, found {versions!r}")
    return [str(versions[name]) for name in BROWSERS]


def restatements(value: str, committed: list[str], generated: list[str]) -> set[str]:
    """Every way of rewriting a header value in the oracle's version numbers.

    One rewrite per browser whose number moved, because no value in the block
    mixes two browsers' versions, and two browsers can share a number -- Chrome
    and Firefox are only three releases apart -- which a single combined pass
    would rewrite with the wrong browser's replacement. A combined pass is
    offered as well, for a hypothetical value that does mix them; extra
    candidates cannot loosen the check, since each is still the committed value
    with nothing but version numbers moved.
    """
    moved = [
        (token, replacement)
        for token, replacement in zip(committed, generated)
        if token != replacement and token in value
    ]
    if not moved:
        return set()

    # One candidate per browser, built off the pairs rather than a token-keyed
    # map, so two browsers sharing a number still each contribute their own.
    candidates = {value.replace(token, replacement) for token, replacement in moved}

    substitutions = dict(moved)
    pattern = "|".join(
        re.escape(token) for token in sorted(substitutions, key=len, reverse=True)
    )
    candidates.add(re.sub(pattern, lambda match: substitutions[match.group(0)], value))
    return candidates


def classify_version_drift(
    committed: Any, generated: Any
) -> tuple[tuple[str, ...], list[str]]:
    """Decide whether a masquerade header mismatch is only the version draw.

    `masquerade_headers.go` is the one oracle whose output is not constant: Xray
    derives every browser version from the current date, offset by a draw from a
    PRNG seeded with the host CPU's identity, so the numbers move with the
    calendar and differ between machines. That oracle's own header says as much
    -- a mismatch there "is a regeneration prompt, not a regression". A CI runner
    will essentially never reproduce the draw of the machine that generated the
    fixtures, so a byte comparison alone would be red on almost every run.

    What survives the draw is still checked strictly: the header keys, their
    casing and their order, and every value carrying no version number. A value
    that does differ is taken in two tiers:

      * restate the committed value in the oracle's version numbers. If that
        reproduces the oracle's value exactly, the value is verified up to the
        draw -- its template is byte-identical, which is the strongest claim
        available. A drifted User-Agent template fails here even though the
        numbers moved.
      * otherwise, excuse it only for `Sec-CH-UA`, and only when the Chrome
        version moved and each side carries its own. That is the one value the
        reference implementation *seeds* with a version rather than merely
        printing it: `common/utils/browser.go` builds it through
        `getGreasedChUa(AnchoredChromeVersion, ...)`, where the major version
        also picks the GREASE brand's punctuation, its fake version, and the
        order of the whole brand list -- so no substitution can reproduce it.
        Values excused this way are named in the report, because an unverified
        value nobody sees is the hole this script exists to close.

        The excuse is deliberately keyed to that header rather than to the
        shape of the value. Any value carrying a Chrome version looks seeded by
        one, so a wider rule would excuse a `User-Agent` whose template had
        genuinely drifted -- a real regression -- whenever it happened to
        coincide with a version bump. `User-Agent` prints the version, so the
        restatement tier above reproduces it exactly and a mismatch there has
        to fail.

    Returns the excused header keys and the reasons to fail; an empty reason
    list means the mismatch was fully explained by the draw.
    """
    if committed.get("variant") != generated.get("variant") or committed.get(
        "user_agent"
    ) != generated.get("user_agent"):
        return (), [
            "the oracle ran with flags the fixture does not record: "
            f"committed variant={committed.get('variant')!r} "
            f"user_agent={committed.get('user_agent')!r}, "
            f"oracle variant={generated.get('variant')!r} "
            f"user_agent={generated.get('user_agent')!r}"
        ]

    committed_versions = committed.get("versions")
    generated_versions = generated.get("versions")
    if committed_versions == generated_versions:
        return (), [
            "the browser versions are identical, so the header block itself has drifted"
        ]

    committed_headers = committed.get("headers", [])
    generated_headers = generated.get("headers", [])
    committed_keys = [entry["key"] for entry in committed_headers]
    generated_keys = [entry["key"] for entry in generated_headers]
    if committed_keys != generated_keys:
        return (), [
            f"header keys differ: committed {committed_keys}, oracle {generated_keys}"
        ]

    committed_tokens = version_tokens(committed_versions)
    generated_tokens = version_tokens(generated_versions)
    committed_chrome = str(committed_versions["chrome"])
    generated_chrome = str(generated_versions["chrome"])

    unverified: list[str] = []
    problems: list[str] = []
    for committed_entry, generated_entry in zip(committed_headers, generated_headers):
        committed_value = committed_entry["value"]
        generated_value = generated_entry["value"]
        if committed_value == generated_value:
            continue
        if generated_value in restatements(
            committed_value, committed_tokens, generated_tokens
        ):
            continue
        seeded_by_chrome_version = (
            committed_entry["key"] == CHROME_SEEDED_HEADER
            and committed_chrome != generated_chrome
            and committed_chrome in committed_value
            and generated_chrome in generated_value
        )
        if seeded_by_chrome_version:
            unverified.append(committed_entry["key"])
            continue
        problems.append(
            f"{committed_entry['key']}: committed {committed_value!r}, "
            f"oracle {generated_value!r}"
        )

    return tuple(unverified), problems


def describe_drift(committed: Any, generated: Any) -> str:
    committed_versions = committed.get("versions", {})
    generated_versions = generated.get("versions", {})
    moved = [
        f"{name} {committed_versions.get(name)}->{generated_versions.get(name)}"
        for name in BROWSERS
        if committed_versions.get(name) != generated_versions.get(name)
    ]
    return ", ".join(moved)


def check_fixture(oracle: Oracle, fixture: Path, document: Any) -> Outcome:
    try:
        flags = oracle.flags(document)
    except ValueError as error:
        return Outcome(fixture, f"cannot derive oracle flags: {error}", failed=True)

    invocation = " ".join([*oracle.command, *flags])
    strict = run_oracle(oracle, [*flags, "-check", str(fixture)])
    if strict.returncode == 0:
        return Outcome(fixture, invocation)

    if not oracle.tolerates_version_drift:
        return Outcome(fixture, f"{invocation}\n{strict.stderr}", failed=True)

    regenerated = run_oracle(oracle, flags)
    if regenerated.returncode != 0:
        return Outcome(
            fixture,
            f"{invocation}\n{regenerated.stderr or strict.stderr}",
            failed=True,
        )

    try:
        generated = json.loads(regenerated.stdout)
        unverified, problems = classify_version_drift(document, generated)
    except (ValueError, KeyError, TypeError) as error:
        return Outcome(
            fixture,
            f"{invocation}\ncannot compare with the oracle: {error}",
            failed=True,
        )

    if problems:
        return Outcome(
            fixture, "\n".join([invocation, *problems]), failed=True
        )

    return Outcome(
        fixture,
        invocation,
        drifted=True,
        note=describe_drift(document, generated),
        unverified=unverified,
    )


def indent(text: str) -> str:
    lines = [line for line in text.rstrip().splitlines() if line.strip()]
    return "\n".join(f"    {line}" for line in lines)


def relative(path: Path) -> str:
    try:
        return str(path.relative_to(REPOSITORY_ROOT))
    except ValueError:
        return str(path)


def owning_oracle(fixture: Path, document: Any) -> Oracle | Outcome:
    """The one oracle that recognises this fixture, or the reason there isn't one."""
    matches = [oracle for oracle in ORACLES if oracle.claims(document)]
    if not matches:
        roots = ", ".join(relative(root) for root in FIXTURE_DIRECTORIES)
        return Outcome(
            fixture,
            f"no oracle claims this fixture; every JSON file under {roots} must be "
            "generated by one, so either teach an oracle to claim it or move it out",
            failed=True,
        )
    if len(matches) > 1:
        return Outcome(
            fixture,
            "claimed by several oracles, so its flags are ambiguous: "
            + ", ".join(oracle.name for oracle in matches),
            failed=True,
        )
    return matches[0]


def main(argv: list[str]) -> int:
    if argv:
        fixtures = [Path(argument).resolve() for argument in argv]
        for fixture in fixtures:
            if not fixture.is_file():
                raise SystemExit(f"no such fixture: {fixture}")
    else:
        fixtures = discover_fixtures()

    if not fixtures:
        raise SystemExit("no fixtures found; the discovery roots must have moved")

    outcomes: list[Outcome] = []
    exercised: set[str] = set()
    for fixture in fixtures:
        try:
            document = json.loads(fixture.read_text())
        except ValueError as error:
            outcome = Outcome(fixture, f"not valid JSON: {error}", failed=True)
        else:
            owner = owning_oracle(fixture, document)
            if isinstance(owner, Outcome):
                outcome = owner
            else:
                exercised.add(owner.name)
                outcome = check_fixture(owner, fixture, document)

        outcomes.append(outcome)
        # Flushed as we go: the run takes long enough that a streaming log is
        # worth having, and it keeps the failure detail below in order with it.
        note = f"  ({outcome.note})" if outcome.note else ""
        print(f"{outcome.status:<5}  {relative(fixture)}{note}", flush=True)
        if outcome.unverified:
            print(
                "       version-seeded values left unverified: "
                + ", ".join(outcome.unverified),
                flush=True,
            )

    failures = [outcome for outcome in outcomes if outcome.failed]
    drifted = [outcome for outcome in outcomes if outcome.drifted]

    print(flush=True)
    for outcome in failures:
        print(f"FAIL {relative(outcome.fixture)}", file=sys.stderr)
        print(indent(outcome.detail), file=sys.stderr)
    sys.stderr.flush()

    print(
        f"{len(outcomes)} fixture(s) checked: "
        f"{len(outcomes) - len(failures) - len(drifted)} reproduced exactly, "
        f"{len(drifted)} reproduced apart from the browser-version draw, "
        f"{len(failures)} failed"
    )

    # Only meaningful over a full run; a filtered run legitimately leaves most
    # oracles idle.
    idle = [oracle.name for oracle in ORACLES if oracle.name not in exercised]
    if not argv and idle:
        print(
            "no fixture is claimed by: "
            + ", ".join(idle)
            + " -- an oracle with no fixture verifies nothing",
            file=sys.stderr,
        )
        return 1

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
