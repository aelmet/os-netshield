#!/usr/local/bin/python3
# Copyright (c) 2025-2026, NetShield Contributors
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# SPDX-License-Identifier: BSD-2-Clause

"""
JWT Helper — RS256 token generation, validation, and revocation for NetShield.
"""

import logging
import os
import sqlite3
import time
import uuid
from typing import Dict, List, Optional

try:
    import jwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.backends import default_backend
except ImportError:
    jwt = None

log = logging.getLogger(__name__)

JWT_SECRET_FILE = "/usr/local/etc/netshield/jwt_secret.key"
JWT_PUBLIC_FILE = "/usr/local/etc/netshield/jwt_public.pem"
JWT_PRIVATE_FILE = "/usr/local/etc/netshield/jwt_private.pem"
JWT_ACCESS_EXPIRY = 900          # 15 minutes
JWT_REFRESH_EXPIRY = 2592000     # 30 days
DB_PATH = "/var/db/netshield/netshield.db"
ISSUER = "netshield"


class JWTManager:
    """Manages RS256 JWT access/refresh tokens with revocation support."""

    def __init__(self):
        if jwt is None:
            raise RuntimeError("PyJWT and cryptography libraries are required")
        self._private_key = None
        self._public_key = None
        self._load_keys()
        self._ensure_db()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_access_token(self, username: str, permissions: List[str] = None) -> str:
        """Generate a short-lived RS256 access token."""
        if permissions is None:
            permissions = []
        now = int(time.time())
        payload = {
            "iss": ISSUER,
            "sub": username,
            "iat": now,
            "exp": now + JWT_ACCESS_EXPIRY,
            "type": "access",
            "permissions": permissions,
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def generate_refresh_token(self, username: str) -> str:
        """Generate a long-lived refresh token with a unique JTI."""
        now = int(time.time())
        jti = str(uuid.uuid4())
        payload = {
            "iss": ISSUER,
            "sub": username,
            "iat": now,
            "exp": now + JWT_REFRESH_EXPIRY,
            "type": "refresh",
            "jti": jti,
        }
        return jwt.encode(payload, self._private_key, algorithm="RS256")

    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate a JWT token. Returns payload dict or None."""
        try:
            payload = jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                options={"verify_exp": True},
            )
            jti = payload.get("jti")
            if jti and self.is_revoked(jti):
                log.debug("Token with jti=%s is revoked", jti)
                return None
            return payload
        except jwt.ExpiredSignatureError:
            log.debug("Token expired")
            return None
        except jwt.InvalidTokenError as exc:
            log.debug("Invalid token: %s", exc)
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Validate a refresh token and issue a new access token."""
        payload = self.validate_token(refresh_token)
        if payload is None:
            return None
        if payload.get("type") != "refresh":
            log.debug("Token is not a refresh token")
            return None
        username = payload.get("sub")
        if not username:
            return None
        self._update_session_last_used(payload.get("jti"))
        return self.generate_access_token(username)

    def revoke_token(self, jti: str) -> None:
        """Add a JTI to the revocation list."""
        try:
            conn = self._db_connect()
            conn.execute(
                "UPDATE mobile_sessions SET revoked = 1 WHERE refresh_jti = ?",
                (jti,),
            )
            conn.commit()
            conn.close()
            log.info("Token jti=%s revoked", jti)
        except Exception as exc:
            log.error("Failed to revoke token: %s", exc)

    def is_revoked(self, jti: str) -> bool:
        """Check whether a JTI has been revoked."""
        try:
            conn = self._db_connect()
            row = conn.execute(
                "SELECT revoked FROM mobile_sessions WHERE refresh_jti = ?",
                (jti,),
            ).fetchone()
            conn.close()
            if row is None:
                return False
            return bool(row[0])
        except Exception as exc:
            log.error("Failed to check revocation: %s", exc)
            return False

    def register_session(
        self,
        username: str,
        jti: str,
        device_name: str = "",
        device_id: str = "",
    ) -> None:
        """Persist a new mobile session after issuing a refresh token."""
        now = int(time.time())
        try:
            conn = self._db_connect()
            conn.execute(
                """INSERT OR REPLACE INTO mobile_sessions
                   (username, refresh_jti, device_name, device_id, created, last_used, revoked)
                   VALUES (?, ?, ?, ?, ?, ?, 0)""",
                (username, jti, device_name, device_id, now, now),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            log.error("Failed to register session: %s", exc)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _generate_key_pair(self) -> None:
        """Generate RSA 2048-bit key pair and save PEM files."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend(),
        )
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        os.makedirs(os.path.dirname(JWT_PRIVATE_FILE), exist_ok=True)
        with open(JWT_PRIVATE_FILE, "wb") as f:
            f.write(private_pem)
        os.chmod(JWT_PRIVATE_FILE, 0o600)

        with open(JWT_PUBLIC_FILE, "wb") as f:
            f.write(public_pem)
        os.chmod(JWT_PUBLIC_FILE, 0o644)

        log.info("Generated new RSA 2048-bit key pair")
        self._private_key = private_key
        self._public_key = private_key.public_key()

    def _load_keys(self) -> None:
        """Load RSA keys from PEM files; generate if missing."""
        if not os.path.exists(JWT_PRIVATE_FILE) or not os.path.exists(JWT_PUBLIC_FILE):
            log.info("JWT key files not found, generating new key pair")
            self._generate_key_pair()
            return

        try:
            with open(JWT_PRIVATE_FILE, "rb") as f:
                self._private_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
            with open(JWT_PUBLIC_FILE, "rb") as f:
                self._public_key = serialization.load_pem_public_key(
                    f.read(), backend=default_backend()
                )
            log.debug("Loaded JWT key pair from disk")
        except Exception as exc:
            log.warning("Failed to load keys (%s), regenerating", exc)
            self._generate_key_pair()

    def _db_connect(self) -> sqlite3.Connection:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        return sqlite3.connect(DB_PATH)

    def _ensure_db(self) -> None:
        """Create the mobile_sessions table if it does not exist."""
        try:
            conn = self._db_connect()
            conn.execute("""
                CREATE TABLE IF NOT EXISTS mobile_sessions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    username    TEXT    NOT NULL,
                    refresh_jti TEXT    NOT NULL UNIQUE,
                    device_name TEXT    DEFAULT '',
                    device_id   TEXT    DEFAULT '',
                    created     INTEGER NOT NULL,
                    last_used   INTEGER NOT NULL,
                    revoked     INTEGER DEFAULT 0
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_jti ON mobile_sessions(refresh_jti)"
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            log.error("Failed to initialise mobile_sessions table: %s", exc)

    def _update_session_last_used(self, jti: Optional[str]) -> None:
        if not jti:
            return
        try:
            conn = self._db_connect()
            conn.execute(
                "UPDATE mobile_sessions SET last_used = ? WHERE refresh_jti = ?",
                (int(time.time()), jti),
            )
            conn.commit()
            conn.close()
        except Exception as exc:
            log.debug("Failed to update last_used: %s", exc)
