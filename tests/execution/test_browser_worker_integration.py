"""Live Docker integration check for the disposable browser session worker.

Skipped unless a Docker daemon is reachable, the browser image is built, and the
operator opts in with ``VULN_PROOF_CLAW_DOCKER_INTEGRATION=1``. A disposable
login form is served on an ``--internal`` network so nothing leaves the host.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import AsyncIterator

import pytest

from vuln_proof_claw.config.models import DockerConfig
from vuln_proof_claw.execution.docker_runtime import SubprocessDockerCommandRunner
from vuln_proof_claw.execution.session_envelope import LoginInstruction
from vuln_proof_claw.sessions.browser_capture import DockerBrowserSessionRunner

_OPT_IN = os.getenv("VULN_PROOF_CLAW_DOCKER_INTEGRATION") == "1"
_BROWSER_IMAGE = "vuln-proof-claw-browser:dev"
_FIXTURE_IMAGE = "python:3.12-slim"
_SUFFIX = str(os.getpid())

pytestmark = pytest.mark.skipif(
    not (_OPT_IN and shutil.which("docker")),
    reason="Docker integration is not enabled",
)

_LOGIN_SERVER = """
import http.server, socketserver
FORM = b"<html><body><form method='POST' action='/login'>" \
    b"<input id='u' name='u'><input id='p' name='p' type='password'>" \
    b"<button id='go' type='submit'>go</button></form></body></html>"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/home'):
            self._send(200, b'<html>welcome</html>')
        else:
            self._send(200, FORM)
    def do_POST(self):
        self.rfile.read(int(self.headers.get('content-length', '0') or 0))
        self.send_response(302)
        self.send_header('Set-Cookie', 'sessionid=abc123; Path=/')
        self.send_header('Location', '/home')
        self.end_headers()
    def _send(self, code, body):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(('0.0.0.0', 8080), H) as httpd:
    httpd.serve_forever()
"""


@pytest.fixture
async def internal_network() -> AsyncIterator[str]:
    runner = SubprocessDockerCommandRunner()
    name = f"vpc-browser-{_SUFFIX}"
    await runner.run(["network", "rm", "--force", name])
    result = await runner.run(["network", "create", "--internal", name])
    assert result.returncode == 0, result.stderr
    try:
        yield name
    finally:
        await runner.run(["network", "rm", "--force", name])


async def test_browser_worker_captures_a_login_session(internal_network: str) -> None:
    runner = SubprocessDockerCommandRunner()
    if (await runner.run(["image", "inspect", _BROWSER_IMAGE])).returncode != 0:
        pytest.skip(f"{_BROWSER_IMAGE} is not built")

    host = f"login-{_SUFFIX}"
    started = await runner.run(
        ["run", "-d", "--rm", "--name", host, "--network", internal_network,
         _FIXTURE_IMAGE, "python", "-c", _LOGIN_SERVER]
    )
    assert started.returncode == 0, started.stderr

    config = DockerConfig(
        runtime_enabled=True,
        browser_image=_BROWSER_IMAGE,
        worker_network=internal_network,
        ownership_label=f"com.vuln-proof-claw.browser-itest-{_SUFFIX}",
    )
    try:
        envelope = await DockerBrowserSessionRunner(config).run(
            LoginInstruction(
                url=f"http://{host}:8080/login",
                username="operator",
                password="hunter2",
                username_selector="#u",
                password_selector="#p",
                submit_selector="#go",
                success_url_substring="/home",
            )
        )
        assert envelope.status == "succeeded", envelope.error_code
        assert "sessionid" in envelope.cookie_names
        cookies = json.loads(envelope.storage_state_json or "")["cookies"]
        assert any(cookie["name"] == "sessionid" for cookie in cookies)
    finally:
        await runner.run(["rm", "--force", host])
