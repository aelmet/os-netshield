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
WebSocket Server — Real-time event push to mobile clients.
Runs on localhost:9443 with TLS. Authenticates via JWT.
"""

import asyncio
import json
import logging
import ssl
import time
from typing import Dict, Optional, Set

try:
    import websockets
    from websockets.server import WebSocketServerProtocol
except ImportError:
    websockets = None
    WebSocketServerProtocol = object

try:
    from .jwt_helper import JWTManager
except ImportError:
    from jwt_helper import JWTManager

log = logging.getLogger(__name__)

VALID_CHANNELS = {"alerts", "bandwidth", "devices", "threats", "dpi"}
HEARTBEAT_INTERVAL = 30  # seconds
MAX_MISSED_PONGS = 3
MAX_TOTAL_CONNECTIONS = 50
MAX_CONNECTIONS_PER_IP = 5


class WSServer:
    """WebSocket server for real-time event push to mobile clients."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 9443,
        cert_path: str = "/usr/local/etc/netshield/ws.pem",
        key_path: str = "/usr/local/etc/netshield/ws.key",
    ):
        self.host = host
        self.port = port
        self.cert_path = cert_path
        self.key_path = key_path
        self._server = None
        self._running = False
        self._jwt = JWTManager()
        # websocket -> set of subscribed channels
        self._connections: Dict[object, Set[str]] = {}
        # websocket -> missed pong count
        self._missed_pongs: Dict[object, int] = {}
        # ip -> connection count (for rate limiting)
        self._ip_connections: Dict[str, int] = {}

    async def start(self) -> None:
        """Start the WebSocket server with TLS."""
        if websockets is None:
            raise RuntimeError("websockets library is not installed")

        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=self.cert_path, keyfile=self.key_path)

        self._running = True
        self._server = await websockets.serve(
            self._handle_connection,
            self.host,
            self.port,
            ssl=ssl_ctx,
        )
        log.info("WSServer started on wss://%s:%d", self.host, self.port)

        # Start heartbeat task
        asyncio.ensure_future(self._heartbeat_loop())

        await self._server.wait_closed()

    async def stop(self) -> None:
        """Gracefully shut down the WebSocket server."""
        self._running = False
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            log.info("WSServer stopped")

    async def _handle_connection(self, websocket) -> None:
        """Handle a new WebSocket connection: authenticate, then process messages."""
        remote = websocket.remote_address
        remote_ip = remote[0] if remote else "unknown"
        log.debug("New connection from %s", remote)

        # Connection limit checks
        if len(self._connections) >= MAX_TOTAL_CONNECTIONS:
            log.warning("Rejected connection from %s: max total connections reached", remote_ip)
            await websocket.close(1013, "Server at capacity")
            return

        current_ip_count = self._ip_connections.get(remote_ip, 0)
        if current_ip_count >= MAX_CONNECTIONS_PER_IP:
            log.warning("Rejected connection from %s: max per-IP connections reached", remote_ip)
            await websocket.close(1013, "Too many connections from this IP")
            return

        self._connections[websocket] = set()
        self._missed_pongs[websocket] = 0
        self._ip_connections[remote_ip] = current_ip_count + 1

        try:
            # Wait for auth message first
            try:
                raw = await asyncio.wait_for(websocket.recv(), timeout=10)
            except asyncio.TimeoutError:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Authentication timeout",
                }))
                return

            msg = json.loads(raw)
            if msg.get("type") != "auth" or not msg.get("token"):
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "First message must be auth",
                }))
                return

            if not self._authenticate(msg["token"]):
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": "Invalid or expired token",
                }))
                return

            await websocket.send(json.dumps({
                "type": "auth_ok",
                "channels_available": sorted(VALID_CHANNELS),
            }))
            log.info("Client authenticated: %s", remote)

            # Process subsequent messages
            async for raw_msg in websocket:
                await self._process_message(websocket, raw_msg)

        except websockets.exceptions.ConnectionClosedOK:
            log.debug("Client %s disconnected cleanly", remote)
        except websockets.exceptions.ConnectionClosedError as exc:
            log.warning("Client %s disconnected with error: %s", remote, exc)
        except json.JSONDecodeError:
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Invalid JSON",
            }))
        except Exception as exc:
            log.exception("Unhandled error for %s: %s", remote, exc)
        finally:
            self._connections.pop(websocket, None)
            self._missed_pongs.pop(websocket, None)
            # Decrement IP connection count
            if remote_ip in self._ip_connections:
                self._ip_connections[remote_ip] -= 1
                if self._ip_connections[remote_ip] <= 0:
                    del self._ip_connections[remote_ip]
            log.debug("Connection cleaned up for %s", remote)

    def _authenticate(self, token: str) -> bool:
        """Validate a JWT token. Returns True if valid."""
        payload = self._jwt.validate_token(token)
        return payload is not None

    async def broadcast(self, channel: str, data: dict) -> None:
        """Send a message to all subscribers of the given channel."""
        if channel not in VALID_CHANNELS:
            log.warning("broadcast called with unknown channel: %s", channel)
            return

        payload = json.dumps({"type": channel, "data": data})
        dead = []
        for ws, channels in list(self._connections.items()):
            if channel in channels:
                try:
                    await ws.send(payload)
                except Exception:
                    dead.append(ws)

        for ws in dead:
            self._connections.pop(ws, None)
            self._missed_pongs.pop(ws, None)

    async def _process_message(self, websocket, message: str) -> None:
        """Handle subscribe/unsubscribe messages from the client."""
        try:
            msg = json.loads(message)
        except json.JSONDecodeError:
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Invalid JSON",
            }))
            return

        msg_type = msg.get("type")
        channels = set(msg.get("channels", []))
        unknown = channels - VALID_CHANNELS

        if msg_type == "subscribe":
            if unknown:
                await websocket.send(json.dumps({
                    "type": "error",
                    "message": f"Unknown channels: {sorted(unknown)}",
                }))
                return
            self._connections[websocket] |= channels
            log.debug("Client subscribed to: %s", channels)

        elif msg_type == "unsubscribe":
            self._connections[websocket] -= channels
            log.debug("Client unsubscribed from: %s", channels)

        elif msg_type == "pong":
            self._missed_pongs[websocket] = 0

        else:
            await websocket.send(json.dumps({
                "type": "error",
                "message": f"Unknown message type: {msg_type}",
            }))

    async def _heartbeat_loop(self) -> None:
        """Send periodic pings; disconnect clients that miss too many."""
        while self._running:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            dead = []
            for ws in list(self._connections.keys()):
                missed = self._missed_pongs.get(ws, 0)
                if missed >= MAX_MISSED_PONGS:
                    log.warning("Client missed %d pongs, disconnecting", missed)
                    dead.append(ws)
                    continue
                try:
                    await ws.ping()
                    self._missed_pongs[ws] = missed + 1
                except Exception:
                    dead.append(ws)

            for ws in dead:
                self._connections.pop(ws, None)
                self._missed_pongs.pop(ws, None)
                try:
                    await ws.close()
                except Exception:
                    pass
