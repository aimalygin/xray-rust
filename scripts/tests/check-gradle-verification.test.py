#!/usr/bin/env python3
"""Exercise checksum verification with real curl retries against a local fixture."""

import hashlib
import importlib.util
from collections import Counter
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "check-gradle-verification.py"
SPEC = importlib.util.spec_from_file_location("gradle_verifier", SCRIPT)
VERIFIER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFIER)
ARTIFACT = b"synthetic Maven artifact\n" * 128
DIGEST = hashlib.sha256(ARTIFACT).hexdigest()


@contextmanager
def repository(*, interrupted=None, artifact=ARTIFACT, sidecar=None, algorithm="sha256"):
    requests = Counter()
    bodies = {
        "/artifact.jar": artifact,
    }
    if algorithm is not None:
        checksum = hashlib.new(algorithm, ARTIFACT, usedforsecurity=False).hexdigest()
        bodies[f"/artifact.jar.{algorithm}"] = (checksum if sidecar is None else sidecar).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests[self.path] += 1
            body = bodies.get(self.path)
            if body is None:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.path == interrupted and requests[self.path] == 1:
                # The first attempt times out after delivering a nonempty prefix.
                # curl retries successfully; stdout cannot retract that prefix.
                self.wfile.write(body[:8])
                self.wfile.flush()
                time.sleep(1.5)
                return
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    # HTTPServer otherwise performs an irrelevant reverse-DNS lookup at bind.
    with patch("http.server.socket.getfqdn", return_value="localhost"):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{server.server_port}/artifact.jar"
    original_arguments = VERIFIER.curl_arguments

    def fixture_arguments(request_url):
        if not request_url.startswith(url):
            raise AssertionError(f"unexpected non-fixture URL: {request_url}")
        args = original_arguments(request_url)
        # Only the loopback fixture uses HTTP and a short timeout. Production
        # curl arguments retain HTTPS-only downloads and their normal bounds.
        args[args.index("--proto") + 1] = "=http"
        args[args.index("--max-time") + 1] = "1"
        args[args.index("--retry") + 1] = "1"
        return args

    try:
        with patch.object(VERIFIER, "curl_arguments", fixture_arguments):
            yield url, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class GradleVerificationTests(unittest.TestCase):
    def test_valid_artifact_matches_both_checksums(self):
        with repository() as (url, _requests):
            VERIFIER.verify_remote_url(url, DIGEST, "fixture")

    def test_legacy_sidecars_still_require_the_locked_sha256(self):
        for algorithm in ("sha1", "md5"):
            with self.subTest(algorithm=algorithm), repository(algorithm=algorithm) as (url, _):
                VERIFIER.verify_remote_url(url, DIGEST, "fixture")
                with self.assertRaisesRegex(VERIFIER.VerificationError, "Gradle SHA-256"):
                    VERIFIER.verify_remote_url(url, "0" * 64, "fixture")

    def test_missing_sidecars_are_rejected(self):
        with repository(algorithm=None) as (url, _requests):
            with self.assertRaisesRegex(VERIFIER.VerificationError, "no checksum sidecar"):
                VERIFIER.verify_remote_url(url, DIGEST, "fixture")

    def test_partial_artifact_timeout_does_not_pollute_successful_retry(self):
        with repository(interrupted="/artifact.jar") as (url, requests):
            VERIFIER.verify_remote_url(url, DIGEST, "fixture")
            self.assertEqual(requests["/artifact.jar"], 2)

    def test_partial_sidecar_timeout_does_not_pollute_successful_retry(self):
        with repository(interrupted="/artifact.jar.sha256") as (url, requests):
            VERIFIER.verify_remote_url(url, DIGEST, "fixture")
            self.assertEqual(requests["/artifact.jar.sha256"], 2)

    def test_artifact_must_match_canonical_sidecar(self):
        with repository(artifact=b"different artifact") as (url, _requests):
            with self.assertRaisesRegex(VERIFIER.VerificationError, "canonical.*sidecar"):
                VERIFIER.verify_remote_url(url, DIGEST, "fixture")

    def test_matching_sidecar_cannot_override_locked_sha256(self):
        with repository() as (url, _requests):
            with self.assertRaisesRegex(VERIFIER.VerificationError, "Gradle SHA-256"):
                VERIFIER.verify_remote_url(url, "0" * 64, "fixture")

    def test_malformed_sidecar_is_rejected(self):
        with repository(sidecar="not a checksum") as (url, _requests):
            with self.assertRaisesRegex(VERIFIER.VerificationError, "invalid canonical"):
                VERIFIER.verify_remote_url(url, DIGEST, "fixture")

    def test_empty_sidecar_is_rejected(self):
        with repository(sidecar="") as (url, _requests):
            with self.assertRaisesRegex(VERIFIER.VerificationError, "invalid canonical"):
                VERIFIER.verify_remote_url(url, DIGEST, "fixture")


if __name__ == "__main__":
    unittest.main()
