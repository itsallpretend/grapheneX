"""grapheneX web interface.

Security posture (see ``docs/security-review.md``):

* binds to loopback by default; a non-loopback bind prints a warning because
  this interface can run privileged hardening commands;
* session cookies are HttpOnly, SameSite=Strict and Secure when HTTPS is
  enabled through ``GRAPHENEX_HTTPS=1``;
* the access token is compared in constant time and the login form is protected
  by a CSRF token plus a simple per-IP lockout;
* Socket.IO only accepts same-origin connections;
* every response carries a restrictive Content-Security-Policy and related
  hardening headers.
"""

from __future__ import annotations

import logging
import os
import secrets
import socket
import webbrowser
from datetime import timedelta

from flask import Flask, request
from flask_socketio import SocketIO

from graphenex.core.cli.shell import Shell
from graphenex.core.utils.helpers import (
    get_flask_secret_key,
    is_loopback,
    is_valid_address,
    is_valid_port,
)
from graphenex.core.utils.logcl import GraphenexLogger

logger = GraphenexLogger(__name__)
logging.getLogger("werkzeug").disabled = True

DEFAULT_HOST = os.environ.get("GRAPHENEX_WEB_HOST", "127.0.0.1")
DEFAULT_PORT = os.environ.get("GRAPHENEX_WEB_PORT", "8080") 
MAX_FORM_BYTES = 64 * 1024

app = Flask(__name__)
app.config.update(
    SECRET_KEY=None,
    ACCESS_TOKEN=None,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=bool(os.environ.get("GRAPHENEX_HTTPS")),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=MAX_FORM_BYTES,
    # Editing modules from the browser executes code as root; opt in explicitly.
    ALLOW_MODULE_AUTHORING=bool(os.environ.get("GRAPHENEX_ALLOW_MODULE_AUTHORING")),
    TEMPLATES_AUTO_RELOAD=False,
)

# An empty allow-list disables cross-origin Socket.IO connections (same-origin only).
socketio = SocketIO(app, cors_allowed_origins=[], logger=False, engineio_logger=False)

default_socket = (DEFAULT_HOST, DEFAULT_PORT)

from graphenex.core.web.views import *  # noqa: E402,F401,F403
from graphenex.core.web.providers import *  # noqa: E402,F401,F403


@app.after_request
def add_security_headers(response):
    """Apply hardening headers to every response."""

    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy", "geolocation=(), microphone=(), camera=()"
    )
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        "form-action 'self'; img-src 'self' data:; object-src 'none'; "
        "script-src 'self'; style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:",
    )
    if app.config.get("SESSION_COOKIE_SECURE"):
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    if request.path.startswith("/static/"):
        response.headers.setdefault("Cache-Control", "public, max-age=86400")
    else:
        response.headers.setdefault("Cache-Control", "no-store")
    return response


def _server_params(args):
    """Return ``(host, port)`` from CLI arguments, falling back to defaults."""

    if args and args.get("host_port"):
        parts = str(args["host_port"]).split(":")
        if len(parts) == 1:
            return parts[0] or DEFAULT_HOST, int(DEFAULT_PORT) if DEFAULT_PORT.isdigit() else 8080
        host, _, port = str(args["host_port"]).rpartition(":")
        return host or DEFAULT_HOST, int(port)
    return DEFAULT_HOST, int(DEFAULT_PORT)


def run_server(args=None, exit_shell=True):
    """Run the web server."""

    secret_key = get_flask_secret_key()
    if not secret_key:
        from graphenex.core.utils.helpers import create_env_file

        secret_key = create_env_file()
    app.config["SECRET_KEY"] = secret_key

    try:
        server_addr, server_port = _server_params(args)
    except (TypeError, ValueError):
        logger.error(f"Invalid socket specified: {args.get('host_port') if args else args}")
        return

    if not is_valid_port(server_port):
        logger.error(f"Invalid port specified: {server_port}")
        return
    if not is_valid_address(server_addr):
        logger.error(f"Invalid address specified: {server_addr}")
        return

    app.config["ACCESS_TOKEN"] = secrets.token_urlsafe(24)
    app.config["SERVER_NAME"] = None

    logger.info(f"Starting server on http://{server_addr}:{server_port}")
    if not is_loopback(server_addr):
        logger.warn(
            "The web interface can run privileged hardening commands and is "
            "listening on a non-loopback address. Put it behind TLS and a "
            "trusted network, or bind to 127.0.0.1."
        )
    try:
        if args and args.get("open", False):
            webbrowser.open(f"http://{server_addr}:{server_port}")

        logger.info(f"Your access token: {app.config['ACCESS_TOKEN']}")
        logger.info("The token is printed once; it is not stored on disk.")
        socketio.run(
            app,
            host=server_addr,
            port=server_port,
            debug=False,
            allow_unsafe_werkzeug=True,
        )
    except OSError as exc:
        if getattr(exc, "errno", None) == 98:
            logger.error(f"{server_addr}:{server_port} is already in use!")
            return
        logger.error(f"Could not start the server: {exc}")
    except KeyboardInterrupt:
        socketio.stop()
        if exit_shell:
            Shell().do_exit(None)
    except Exception as exc:  # pragma: no cover - last resort logging
        logger.error(f"An error occurred: {exc}")
