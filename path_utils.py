from __future__ import annotations

"""Shared helpers for resolving project-relative paths."""

import os
from pathlib import Path
from typing import Union

PathLike = Union[str, Path]


def get_base_dir() -> Path:
    """Return the project root, honoring the QR_SCANNER_HOME override."""
    env_path = os.environ.get("QR_SCANNER_HOME")
    if env_path:
        base = Path(os.path.expandvars(env_path)).expanduser()
        return base.resolve()
    return Path(__file__).resolve().parent


def resolve_path(path_like: PathLike) -> Path:
    """Resolve a path relative to the project root when not absolute."""
    if path_like is None:
        raise ValueError("path_like must not be None")

    path = Path(os.path.expandvars(str(path_like))).expanduser()
    if path.is_absolute():
        return path
    return get_base_dir() / path


def ensure_directory(path_like: PathLike) -> Path:
    """Ensure a directory exists and return its resolved path."""
    path = resolve_path(path_like)
    path.mkdir(parents=True, exist_ok=True)
    return path
