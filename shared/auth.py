"""One shared login credential for the whole product -- the web
dashboard and the terminal console both gate on this, so an analyst
only has one password to remember (or forget) rather than two separate
ones that happen to work the same way.

Mandatory, not opt-in: neither interface has any other app-level auth,
so without a password anyone who can reach the dashboard's port or run
the terminal console is in. If DASHBOARD_PASSWORD isn't set, fall back
to a default account instead of falling open, the same way Jupyter
prints a first-run token rather than binding with no auth at all.
"""
import os

DEFAULT_DASHBOARD_USERNAME = "user"
DEFAULT_DASHBOARD_PASSWORD = "user"


def resolve_dashboard_password(warn: bool = True) -> str:
    """Returns DASHBOARD_PASSWORD if set, else the default account's
    password. When warn is True and the default is in use, prints a
    console notice naming it explicitly -- callers that rerun on every
    interaction (Streamlit) should only pass warn=True from behind
    their own once-per-process guard; callers that are a normal
    long-running process (the terminal console) can call this once at
    import time with warn=True directly.
    """
    configured = os.getenv("DASHBOARD_PASSWORD", "")
    if configured:
        return configured
    if warn:
        print(
            "\n" + "=" * 64 +
            f"\n  DASHBOARD_PASSWORD not set -- using the default account "
            f"({DEFAULT_DASHBOARD_USERNAME}/{DEFAULT_DASHBOARD_PASSWORD}).\n"
            "  Set DASHBOARD_PASSWORD before this is reachable by anyone\n"
            "  other than you.\n" +
            "=" * 64 + "\n",
            flush=True,
        )
    return DEFAULT_DASHBOARD_PASSWORD
