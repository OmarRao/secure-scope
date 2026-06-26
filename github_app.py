"""
GitHub App authentication — JWT-based token exchange and webhook verification.
"""

import hashlib
import hmac
import time
from typing import Optional

import jwt
import requests


def generate_jwt(app_id: str, private_key_pem: str) -> str:
    """
    Create a GitHub App JWT valid for 10 minutes.

    Args:
        app_id:          GitHub App ID (from App settings page).
        private_key_pem: PEM-encoded RSA private key string.

    Returns:
        Signed JWT string.
    """
    now = int(time.time())
    payload = {
        "iat": now - 60,   # issued 60s ago to account for clock skew
        "exp": now + (10 * 60),  # expires in 10 minutes
        "iss": str(app_id),
    }
    token = jwt.encode(payload, private_key_pem, algorithm="RS256")
    # PyJWT >=2.0 returns str directly; <2.0 returns bytes
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token


def get_installation_token(
    app_id: str, private_key_pem: str, installation_id: str
) -> str:
    """
    Exchange a GitHub App JWT for an installation access token.

    Args:
        app_id:           GitHub App ID.
        private_key_pem:  PEM-encoded RSA private key.
        installation_id:  GitHub App installation ID.

    Returns:
        Installation access token string.
    """
    jwt_token = generate_jwt(app_id, private_key_pem)
    resp = requests.post(
        f"https://api.github.com/app/installations/{installation_id}/access_tokens",
        headers={
            "Authorization": f"Bearer {jwt_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()["token"]


def verify_webhook_signature(payload: bytes, secret: str, signature: str) -> bool:
    """
    Verify a GitHub webhook HMAC-SHA256 signature.

    Args:
        payload:   Raw request body bytes.
        secret:    Webhook secret string.
        signature: Value of X-Hub-Signature-256 header.

    Returns:
        True if signature is valid.
    """
    if not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature)


class GitHubAppWebhookServer:
    """
    Webhook server that uses GitHub App installation token auth.
    Extends the core webhook server logic from webhook.py.
    """

    def __init__(
        self,
        app_id: str,
        private_key_pem: str,
        installation_id: str,
        port: int = 8080,
        secret: str = "",
        out_dir: str = "reports",
    ):
        self.app_id = app_id
        self.private_key_pem = private_key_pem
        self.installation_id = installation_id
        self.port = port
        self.secret = secret
        self.out_dir = out_dir
        self._token: Optional[str] = None

    def get_token(self) -> str:
        """Return a fresh installation token (re-fetches on demand)."""
        self._token = get_installation_token(
            self.app_id, self.private_key_pem, self.installation_id
        )
        return self._token

    def run(self) -> None:
        """Start the webhook server using an installation token."""
        token = self.get_token()
        from webhook import run_webhook_server
        run_webhook_server(
            port=self.port,
            secret=self.secret,
            out_dir=self.out_dir,
            github_token=token,
        )
