"""Per-session (per-tenant-JWT) reads of the T-SOC API for the web
dashboard's own pages (command_center, investigate, network, health).

Deliberately NOT shared/data_access.py's DataStreamManager: that class is
a process-wide singleton, authenticated with one static, all-tenant
TSOC_API_KEY, that polls in a background thread and caches results in
instance attributes shared by every Streamlit session in the process.
That's the right shape for dashboard/cli_dashboard.py's single-operator
terminal tool, but wrong here -- one dashboard process now serves many
tenants' employees concurrently, and every employee's session must only
ever see their own tenant's data. Before this module existed, every
logged-in employee saw every tenant's alerts/incidents/stats on these
four pages, regardless of which tenant they actually belonged to,
because they all read the same singleton's cached state.

Each function below reads the *current* session's own JWT
(st.session_state["access_token"], set by dashboard/app.py's login) and
calls shared/data_access.py's tenant-scoped fetch_alerts()/fetch_stats()
-- the same functions terminal/tsoc_console.py uses for the same reason.
Results are cached briefly per-token via st.cache_data so rapid Streamlit
reruns (a filter change, a row click) don't each trigger a fresh round
trip, while still keeping different users' cached data completely
separate (the token is part of the cache key).
"""
import time

import streamlit as st

from shared.data_access import fetch_alerts, fetch_stats, synthesize_incidents

# Short enough that the dashboard still feels live (comparable to
# DataStreamManager's 2s background poll interval), long enough to
# absorb several reruns from the same user interaction (a filter change
# plus the resulting row-selection rerun) as one round trip apiece.
_CACHE_TTL_SEC = 3

_EMPTY_STATS = {"total_alerts": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}


def _token() -> str:
    return st.session_state["access_token"]


@st.cache_data(ttl=_CACHE_TTL_SEC, show_spinner=False)
def _cached_alerts(token: str) -> list:
    return fetch_alerts(token)


@st.cache_data(ttl=_CACHE_TTL_SEC, show_spinner=False)
def _cached_stats(token: str) -> dict:
    return fetch_stats(token)


def get_alerts() -> list:
    """This session's tenant's alerts, or [] on any failure -- every page
    that calls this already treats an empty/broker-unavailable reading as
    a first-class UI state (dashboard/components/empty_states.py), the
    same contract DataStreamManager.get_alerts() offered (it never raised
    either, just returned whatever it last polled, possibly nothing)."""
    try:
        return _cached_alerts(_token())
    except Exception:
        return []


def get_incidents() -> list:
    return synthesize_incidents(get_alerts())


def status() -> dict:
    """Shape-compatible with DataStreamManager.status() so command_center,
    investigate, network, and health don't need bespoke health-check
    logic -- broker_healthy here means "this session's own authenticated
    read just succeeded", not a shared, cross-tenant reading of the whole
    pipeline that says nothing about whether *this* employee's tenant is
    actually reachable.

    last_event_time persists in this session's own state (not a fresh
    time.time() every call) so a failed read after a previous success can
    still report *when* it was last known-good -- health.py's staleness
    label depends on that distinction, not just a plain up/down flag.
    """
    try:
        alerts = _cached_alerts(_token())
        stats = _cached_stats(_token())
    except Exception:
        return {
            "broker_healthy": False,
            "last_event_time": st.session_state.get("_session_data_last_good", 0.0),
            "incident_count": 0,
            "alert_count": 0,
            "stats": _EMPTY_STATS,
        }

    st.session_state["_session_data_last_good"] = time.time()
    return {
        "broker_healthy": True,
        "last_event_time": st.session_state["_session_data_last_good"],
        "incident_count": len(alerts),
        "alert_count": len(alerts),
        "stats": stats,
    }
