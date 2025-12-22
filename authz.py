from __future__ import annotations

import os
from functools import wraps
from typing import Any, Callable, Dict, Optional, Tuple


ROLE_ORDER: Dict[str, int] = {
    "viewer": 0,
    "shop": 1,
    "admin": 2,
}


def _norm_role(role: Optional[str]) -> str:
    r = (role or "").strip().lower()
    return r if r in ROLE_ORDER else "viewer"


def is_auth_enabled() -> bool:
    """Enable auth only when at least one password is configured.

    This keeps existing local installs working unchanged unless you opt-in
    by setting environment variables.
    """
    return bool((os.environ.get("INNOSAW_ADMIN_PASSWORD") or "").strip() or (os.environ.get("INNOSAW_SHOP_PASSWORD") or "").strip())


def current_role(session: Dict[str, Any]) -> str:
    role = session.get("innosaw_role")
    if role:
        return _norm_role(str(role))

    # Back-compat with existing admin flow
    if session.get("admin_authenticated"):
        return "admin"

    return "viewer"


def set_role(session: Dict[str, Any], role: str) -> None:
    session["innosaw_role"] = _norm_role(role)
    # Keep old flag in sync for older templates/logic
    session["admin_authenticated"] = (session["innosaw_role"] == "admin")


def clear_role(session: Dict[str, Any]) -> None:
    session.pop("innosaw_role", None)
    session.pop("admin_authenticated", None)


def check_password(password: str) -> Tuple[bool, str]:
    """Validate password against env vars.

    Returns (ok, role). Role is one of viewer/shop/admin.
    """
    pw = (password or "").strip()
    admin_pw = (os.environ.get("INNOSAW_ADMIN_PASSWORD") or "").strip()
    shop_pw = (os.environ.get("INNOSAW_SHOP_PASSWORD") or "").strip()

    if admin_pw and pw == admin_pw:
        return True, "admin"
    if shop_pw and pw == shop_pw:
        return True, "shop"
    return False, "viewer"


def has_role(session: Dict[str, Any], required: str) -> bool:
    have = ROLE_ORDER[current_role(session)]
    need = ROLE_ORDER[_norm_role(required)]
    return have >= need


def require_role(required: str, *, error_message: Optional[str] = None):
    """Flask route decorator.

    If auth is not enabled, allows the request (backwards compatible).
    If enabled, requires current session role >= required.
    """

    def decorator(fn: Callable[..., Any]):
        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any):
            # Import locally so this module can be imported without Flask in tooling scripts.
            from flask import jsonify, request, session

            if not is_auth_enabled():
                return fn(*args, **kwargs)

            if has_role(session, required):
                return fn(*args, **kwargs)

            msg = error_message or "Not authorized. Enter a password to enable saving."
            return (
                jsonify(
                    {
                        "error": msg,
                        "required_role": _norm_role(required),
                        "current_role": current_role(session),
                        "login_url": "/login",
                    }
                ),
                403,
            )

        return wrapper

    return decorator
