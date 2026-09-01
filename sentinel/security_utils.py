"""Shared filesystem-protection helpers for the Sentinel security subsystem."""

import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def apply_owner_only_dacl(path: Path) -> None:
    """
    Restricts a file on Windows to the current user, SYSTEM, and
    Administrators only. No-op on non-Windows. Never raises — logs a
    warning and leaves default permissions in place on any failure,
    consistent with how the rest of this codebase handles degraded-
    security paths.
    """
    if os.name != "nt":
        return

    try:
        import win32api
        import win32security
        import ntsecuritycon

        proc = win32api.GetCurrentProcess()
        token_handle = win32security.OpenProcessToken(proc, win32security.TOKEN_QUERY)
        user_sid, _ = win32security.GetTokenInformation(token_handle, win32security.TokenUser)
        sys_sid = win32security.CreateWellKnownSid(win32security.WinLocalSystemSid, None)
        admin_sid = win32security.CreateWellKnownSid(win32security.WinBuiltinAdministratorsSid, None)

        dacl = win32security.ACL()
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, sys_sid)
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, admin_sid)

        sd = win32security.SECURITY_DESCRIPTOR()
        sd.SetSecurityDescriptorDacl(1, dacl, False)
        win32security.SetFileSecurity(
            str(path),
            win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
            sd,
        )
    except Exception as e:
        logger.warning("Could not set Windows DACL on %s (%s); default permissions apply.", path, e)
