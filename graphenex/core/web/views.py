"""HTTP routes and Socket.IO events for the web interface."""

from __future__ import annotations

import re
import secrets
import time
from functools import wraps

from flask import (
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
)
from flask_socketio import emit, request as socket_request

from graphenex.core.hrd.journal import Journal
from graphenex.core.hrd.recovery import revert_record
from graphenex.core.hrd.schema import (
    ModuleValidationError,
    normalize_module,
)
from graphenex.core.utils import helpers
from graphenex.core.utils.helpers import get_mod_json, get_modules
from graphenex.core.utils.logcl import GraphenexLogger
from graphenex.core.utils.sysinfo import SysInformation
from graphenex.core.web import app, socketio

logger = GraphenexLogger(__name__)

module_dict = get_modules()
_namespaces = list(module_dict.keys())
_default_namespace = _namespaces[0] if _namespaces else ""

#: Per-connection UI state; avoids leaking one operator's namespace to another.
_connection_namespace: dict[str, str] = {}

#: Simple in-memory lockout for the token form (per client address).
_login_failures: dict[str, list[float]] = {}
MAX_LOGIN_FAILURES = 5
LOGIN_WINDOW_SECONDS = 300

SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{8,128}$")


def _safe_equal(left, right) -> bool:
    """Constant-time comparison that tolerates ``None``."""

    if left is None or right is None:
        return False
    return secrets.compare_digest(str(left).encode(), str(right).encode())


def _client_ip() -> str:
    return request.remote_addr or "unknown"


def _recent_failures(ip: str) -> list[float]:
    now = time.time()
    failures = [
        stamp
        for stamp in _login_failures.get(ip, [])
        if now - stamp < LOGIN_WINDOW_SECONDS
    ]
    _login_failures[ip] = failures
    return failures


def _record_failure(ip: str) -> None:
    failures = _recent_failures(ip)
    failures.append(time.time())
    _login_failures[ip] = failures


def _csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def login_required(view):
    @wraps(view)
    def decorated_function(*args, **kwargs):
        if not _safe_equal(session.get("token"), app.config.get("ACCESS_TOKEN")):
            return redirect("/auth")
        return view(*args, **kwargs)

    return decorated_function


def auth_socketio(view):
    """Only allow socket events from an authenticated same-origin session."""

    @wraps(view)
    def decorated_function(*args, **kwargs):
        if not _safe_equal(session.get("token"), app.config.get("ACCESS_TOKEN")):
            emit("auth", {"text": "Not authenticated"})
            return None
        return view(*args, **kwargs)

    return decorated_function


def _connection_id() -> str:
    sid = getattr(socket_request, "sid", None)
    return sid or "anonymous"


def _current_namespace() -> str:
    return _connection_namespace.get(_connection_id(), _default_namespace)


def _set_namespace(namespace: str) -> None:
    _connection_namespace[_connection_id()] = namespace


@app.route("/auth", methods=["GET", "POST"])
def auth():
    if _safe_equal(session.get("token"), app.config.get("ACCESS_TOKEN")):
        return redirect("/")

    ip = _client_ip()
    if len(_recent_failures(ip)) >= MAX_LOGIN_FAILURES:
        response = render_template(
            "auth.html",
            csrf_token=_csrf_token(),
            locked=True,
            retry_after=LOGIN_WINDOW_SECONDS,
        )
        return response, 429, {"Retry-After": str(LOGIN_WINDOW_SECONDS)}

    if request.method == "POST":
        form_token = request.form.get("csrf_token", "")
        if not _safe_equal(form_token, session.get("csrf_token")):
            logger.warn(f"Rejected login without a valid CSRF token from {ip}.")
            abort(400, "invalid CSRF token")

        token = request.form.get("token", "")
        if SAFE_TOKEN_RE.match(token) and _safe_equal(token, app.config.get("ACCESS_TOKEN")):
            _login_failures.pop(ip, None)
            session.clear()
            session["token"] = token
            session["csrf_token"] = secrets.token_urlsafe(32)
            session.permanent = True
            logger.info(f"Web session authenticated from {ip}.")
            return redirect("/")

        _record_failure(ip)
        logger.warn(f"Failed web authentication from {ip}.")
        flash("Token is not valid", "error")

    return render_template("auth.html", csrf_token=_csrf_token(), locked=False)


@app.route("/")
@login_required
def main():
    return render_template(
        "index.html",
        title="grapheneX [Web]",
        mod_count=get_mod_count(module_dict),
        sys_all_info=SysInformation.get_all_info(),
        authoring=app.config.get("ALLOW_MODULE_AUTHORING", False),
    )


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


def get_mod_count(mod_dict):
    """Return the count of modules in the dict."""

    return sum(len(value) for value in mod_dict.values())


@socketio.on("disconnect")
def on_disconnect(*args):
    _connection_namespace.pop(_connection_id(), None)


@socketio.on("get_namespaces")
@auth_socketio
def send_namespaces(data=None):
    """Send namespaces to the web."""

    emit("get_namespaces", {"namespaces": list(module_dict.keys())})


@socketio.on("get_current_namespace")
@auth_socketio
def send_current_namespace(data=None):
    """Send the namespace this connection is currently looking at."""

    emit("get_current_namespace", {"current_namespace": _current_namespace()})


@socketio.on("send_current_namespace")
@auth_socketio
def get_current_namespace(namespace):
    """Set the current namespace for this connection and send its modules."""

    if not isinstance(namespace, str):
        emit("log_message", {"tag": "danger", "content": "Invalid namespace."})
        return
    definitions = module_dict.get(namespace)
    if definitions is None:
        logger.warn(f'Non-existent namespace: "{namespace}".')
        emit("log_message", {"tag": "warning", "content": "Unknown namespace."})
        return

    _set_namespace(namespace)
    modules = [
        {
            "name": name,
            "desc": module.desc,
            "source": module.command,
            "check": module.check_command,
            "revert": module.revert_command,
            "risk": module.risk,
            "cis": list(module.cis),
            "revertible": module.revertible,
            "revert_strategy": module.revert_strategy,
            "requires_restart": bool(module.require_restart),
            "requires_root": bool(module.require_superuser),
        }
        for name, module in definitions.items()
    ]
    logger.info(f'Sending modules of "{namespace}".')
    emit("get_module", modules)


@socketio.on("search_module")
@auth_socketio
def search_module(data):
    """Search module names and descriptions in the current namespace."""

    namespace = _current_namespace()
    definitions = module_dict.get(namespace, {})
    query = str((data or {}).get("query", "")).lower()
    result = [
        {
            "name": name,
            "desc": module.desc,
            "source": module.command,
            "risk": module.risk,
            "cis": list(module.cis),
            "revertible": module.revertible,
            "revert_strategy": module.revert_strategy,
            "requires_restart": bool(module.require_restart),
            "requires_root": bool(module.require_superuser),
        }
        for name, module in definitions.items()
        if query in name.lower() or query in module.desc.lower()
    ]
    emit("search_module", {"result": result})


@socketio.on("harden")
@auth_socketio
def harden(module_name):
    """Apply a module and report the journaled run to the browser."""

    namespace = _current_namespace()
    module = module_dict.get(namespace, {}).get(module_name)
    if module is None:
        emit("log_message", {"tag": "danger", "content": "Unknown module."})
        emit(str(module_name) + "_log", {"state": "error"})
        return

    emit(module_name + "_log", {"msg": "Running: " + module.command, "state": "output"})
    try:
        outcome = module.apply(journal=Journal())
    except PermissionError as exc:
        message = str(exc)
        emit("log_message", {"tag": "warning", "content": message, "duration": 3000})
        emit(module_name + "_log", {"msg": message, "state": "error"})
        logger.error(message)
        return
    except Exception as exc:  # pragma: no cover - unexpected failures
        logger.error(f"Failed to execute hardening command: {exc}")
        emit("log_message", {"tag": "danger", "content": "Hardening failed."})
        emit(module_name + "_log", {"msg": str(exc), "state": "error"})
        return

    if outcome.already_compliant:
        emit(module_name + "_log", {"msg": "Already compliant; nothing to do.", "state": "success"})
        emit("log_message", {"tag": "success", "content": "Already compliant."})
        return

    if outcome.result.stdout:
        emit(module_name + "_log", {"msg": outcome.result.stdout, "state": "output"})
    if outcome.result.stderr:
        emit(module_name + "_log", {"msg": outcome.result.stderr, "state": "output"})

    if not outcome.ok:
        message = "Hardening failed: " + outcome.result.summary(300)
        emit(module_name + "_log", {"msg": message, "state": "error"})
        emit("log_message", {"tag": "danger", "content": "Hardening failed.", "duration": 3000})
        logger.error(message)
        return

    if outcome.verified is False:
        emit(
            module_name + "_log",
            {"msg": "Audit still reports drift after applying this module.", "state": "output"},
        )
        emit("log_message", {"tag": "warning", "content": "Applied, but the audit reports drift."})
    else:
        emit("log_message", {"tag": "success", "content": "Hardening command executed successfully."})

    emit(
        module_name + "_log",
        {
            "msg": f"Run {outcome.run_id} recorded. Undo with the Revert button or 'grapheneX --revert {outcome.run_id}'.",
            "state": "success",
            "run_id": outcome.run_id,
        },
    )
    if outcome.restart_required:
        emit(
            module_name + "_log",
            {"msg": "A restart is required for this change to take effect.", "state": "output"},
        )
    emit("run_recorded", _run_payload(outcome.run_id))
    logger.info(f"Applied {module.qualified_name} (run {outcome.run_id}).")


@socketio.on("check_module")
@auth_socketio
def check_module(module_name):
    """Run the audit command of a module without changing anything."""

    module = module_dict.get(_current_namespace(), {}).get(module_name)
    if module is None:
        emit("log_message", {"tag": "danger", "content": "Unknown module."})
        return
    result = module.check()
    state = "compliant" if result.ok else "drift"
    emit(module_name + "_log", {"msg": f"Audit ({state}): {result.summary(300)}", "state": state})
    emit(
        "log_message",
        {
            "tag": "success" if result.ok else "warning",
            "content": f"{module.name}: {state}",
            "duration": 2000,
        },
    )


def _run_payload(run_id):
    record = Journal().get(run_id)
    return {"run_id": run_id, "record": record.to_dict() if record else None}


@socketio.on("get_history")
@auth_socketio
def get_history(data=None):
    """Return recent journal entries plus the integrity status."""

    journal = Journal()
    limit = 20
    if isinstance(data, dict):
        try:
            limit = max(1, min(200, int(data.get("limit", 20))))
        except (TypeError, ValueError):
            limit = 20
    chain_ok, problems = journal.verify_chain()
    emit(
        "get_history",
        {
            "records": [record.to_dict() for record in journal.history(limit)],
            "pending": [record.run_id for record in journal.pending()],
            "chain_ok": chain_ok,
            "problems": problems,
        },
    )


@socketio.on("revert_run")
@auth_socketio
def revert_run(data):
    """Revert a journaled run (or the most recent pending run)."""

    journal = Journal()
    spec = "last"
    if isinstance(data, dict):
        spec = str(data.get("run_id") or "last")
    if spec == "last":
        pending = journal.pending()
        record = pending[0] if pending else None
    else:
        record = journal.get(spec)
    if record is None:
        emit("log_message", {"tag": "warning", "content": "Nothing to revert."})
        emit("revert_result", {"ok": False, "error": "no matching run"})
        return

    outcome = revert_record(record, journal=journal)
    if outcome.ok:
        emit(
            "log_message",
            {"tag": "success", "content": f"Reverted {record.module}."},
        )
    else:
        emit(
            "log_message",
            {"tag": "danger", "content": "Revert failed: " + (outcome.error or "see log"), "duration": 4000},
        )
    emit("revert_result", outcome.to_dict())
    emit("run_recorded", _run_payload(record.run_id))
    logger.info(f"Reverted {record.module} (run {record.run_id}).")


@socketio.on("add_module")
@auth_socketio
def add_module(payload):
    """Add a module from the browser (opt-in through GRAPHENEX_ALLOW_MODULE_AUTHORING)."""

    global module_dict

    if not app.config.get("ALLOW_MODULE_AUTHORING"):
        emit(
            "log_message",
            {
                "tag": "warning",
                "content": "Module authoring is disabled. Set "
                "GRAPHENEX_ALLOW_MODULE_AUTHORING=1 to enable it, or use the CLI.",
                "duration": 4000,
            },
        )
        return

    try:
        if not isinstance(payload, dict):
            raise ValueError("invalid payload")
        candidate = {
            "name": payload.get("name", ""),
            "desc": payload.get("desc", ""),
            "command": payload.get("cmd", payload.get("command", "")),
            "check": payload.get("check", ""),
            "revert": payload.get("revert", ""),
            "files": payload.get("files") or [],
            "shell": bool(payload.get("shell", False)),
            "require_superuser": bool(payload.get("su", False)),
            "require_restart": bool(payload.get("rr", False)),
            "risk": payload.get("risk", "medium"),
            "target_os": helpers.target_os_name(),
        }
        module = normalize_module(candidate)
        namespace = payload.get("ns", "")
        data = get_mod_json()
        data.setdefault(namespace, []).append(
            {key: value for key, value in module.items() if key != "issues"}
        )
        helpers.save_mod_json(data)
    except ModuleValidationError as exc:
        for issue in exc.issues:
            logger.error(f"Module validation: {issue}")
        emit(
            "log_message",
            {"tag": "danger", "content": f"Module rejected: {exc.issues[0]}", "duration": 5000},
        )
        return
    except Exception as exc:
        logger.error(f"Error occurred while adding new module: {exc}")
        emit(
            "log_message",
            {"tag": "warning", "content": f"Could not add module: {exc}", "duration": 4000},
        )
        return

    module_dict = get_modules()
    emit("new_module_added", get_mod_count(module_dict))
    emit(
        "log_message",
        {"tag": "success", "content": "Module added and validated."},
    )
    logger.info(f"Added module {namespace}/{module['name']} from the web interface.")
