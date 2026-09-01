"""Shared filesystem-protection helpers for the audit subsystem.

Re-exports core security helpers from sentinel.security_utils for backward compatibility.
"""

from sentinel.security_utils import apply_owner_only_dacl

__all__ = ["apply_owner_only_dacl"]
