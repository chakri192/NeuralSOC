"""Shared, reusable UI building blocks for every dashboard page: theme
injection, severity/status badges, relative timestamps, and small HTML
components (KPI cards, connection pill) that st.metric/st.info can't
give enough visual control over for a daily-use ops screen.
"""
import html
import os
from datetime import datetime, timezone

import dateutil.parser
import streamlit as st

from dashboard.components.icons import svg
from dashboard.theme import SEVERITY_COLORS, STATUS_COLORS, STATUS_LABELS, css_variables
from shared.formatters import categorize_evidence

_CSS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "styles", "app.css")


def inject_theme() -> None:
    """Applies the palette as CSS custom properties (mirroring
    .streamlit/config.toml's [theme] section), then loads the static
    stylesheet that consumes them. Call once near the top of every page."""
    with open(_CSS_PATH, "r") as f:
        base_css = f.read()
    st.markdown(f"<style>\n{css_variables()}\n{base_css}\n</style>", unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    severity = (severity or "low").lower()
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["low"])
    label = html.escape(severity.upper())
    return f'<span class="tsoc-badge" style="--badge-color:{color};">{label}</span>'


def status_badge(status: str) -> str:
    status = (status or "open").lower()
    color = STATUS_COLORS.get(status, STATUS_COLORS["open"])
    label = html.escape(STATUS_LABELS.get(status, status.replace("_", " ").title()))
    return f'<span class="tsoc-badge tsoc-badge--status" style="--badge-color:{color};">{label}</span>'


def relative_time(iso_str: str) -> str:
    """'2m ago' / '3h ago', falling back to a plain date once the delta
    is too coarse to matter -- an analyst deciding what to work next
    cares about "recent vs stale", not a precise duration."""
    if not iso_str:
        return "Unknown"
    try:
        dt = dateutil.parser.isoparse(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        seconds = (datetime.now(timezone.utc) - dt).total_seconds()
        if seconds < 60:
            return "just now"
        if seconds < 3600:
            return f"{int(seconds // 60)}m ago"
        if seconds < 86400:
            return f"{int(seconds // 3600)}h ago"
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return "Unknown"


def kpi_card(label: str, value: str, tone: str = "neutral", sublabel: str = "") -> str:
    """One KPI tile as raw HTML (st.metric has no per-card accent
    color). tone matches a severity key ("critical"/"high"/"medium"/
    "low") or "neutral"/"accent"."""
    color_map = {**SEVERITY_COLORS, "neutral": "var(--text-muted)", "accent": "var(--accent)"}
    color = color_map.get(tone, "var(--text-muted)")
    sub = f'<div class="tsoc-kpi__sub">{sublabel}</div>' if sublabel else ""
    return (
        f'<div class="tsoc-kpi" style="--kpi-color:{color};">'
        f'<div class="tsoc-kpi__label">{label}</div>'
        f'<div class="tsoc-kpi__value">{value}</div>{sub}</div>'
    )


def kpi_row(cards: list) -> None:
    """cards: kpi_card(...) HTML strings, laid out as an even CSS grid
    (not st.columns) so card heights stay aligned regardless of
    whether a given card has a sublabel."""
    st.markdown(f'<div class="tsoc-kpi-row">{"".join(cards)}</div>', unsafe_allow_html=True)


def mono(value) -> str:
    """Escaped, monospace-styled inline HTML fragment -- the one way any
    page should embed a single attacker-influenced alert field (an
    incident ID, an IP) inside markup rendered with
    unsafe_allow_html=True. The escaping happens inside this function,
    not at each call site, so a future page can't render one of these
    fields unescaped just by forgetting an html.escape() call -- see
    SECURITY.md's stored-XSS finding this replaced hand-rolled
    f'<span class="tsoc-mono">{html.escape(...)}</span>' call sites
    with."""
    return f'<span class="tsoc-mono">{html.escape(str(value))}</span>'


def safe_html(value) -> str:
    """HTML-escaped text for embedding inside unsafe_allow_html=True
    markup outside of a mono() span (e.g. a threat class name next to a
    severity badge). Same rationale as mono() above."""
    return html.escape(str(value))


def _kv_rows_html(pairs: dict) -> str:
    rows = "".join(
        f'<div class="tsoc-kv__row"><span class="tsoc-kv__key">{html.escape(str(k))}</span>'
        f'<span class="tsoc-kv__val">{html.escape(str(v))}</span></div>'
        for k, v in pairs.items()
    )
    return f'<div class="tsoc-kv">{rows}</div>'


def render_evidence_columns(evidence: dict) -> None:
    """Splits one alert's evidence dict into Observed Facts (network-
    level, attacker-influenced) vs Inferred & Model Outputs (scores,
    latency) side by side. The one place this renders an alert's
    evidence -- used by both the Incidents detail panel and Investigate
    -- so the two never drift into different visual treatments of the
    same data again."""
    obs, inf, _unk = categorize_evidence(evidence)
    col_o, col_i = st.columns(2)
    with col_o:
        st.markdown("**Observed Facts**")
        st.markdown(_kv_rows_html(obs), unsafe_allow_html=True)
    with col_i:
        st.markdown("**Inferred & Model Outputs**")
        st.markdown(_kv_rows_html(inf), unsafe_allow_html=True)


def connection_pill(healthy: bool) -> str:
    dot = svg("dot", size=8)
    if healthy:
        return f'<span class="tsoc-pill tsoc-pill--ok">{dot} Live</span>'
    return f'<span class="tsoc-pill tsoc-pill--down">{dot} Disconnected</span>'
