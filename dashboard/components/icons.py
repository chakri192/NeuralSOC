"""Hand-authored inline SVG icons -- no emoji anywhere in the UI.

Each icon is a 16x16 stroke-based glyph using currentColor, so it
inherits whatever text color CSS applies at its call site (a badge, a
button, a KPI card, a pill) without a separate color token per icon.

Streamlit's own icon slots (st.Page(icon=...), st.set_page_config
(page_icon=...), st.button(icon=...)) don't accept raw SVG -- only an
emoji or a ":material/name:" Material Symbols shortcode -- so those
call sites use the material shortcode form instead; everything else
that's plain HTML we render ourselves uses svg() below.
"""

_ICONS = {
    "shield": '<path d="M8 1.2l6 2.3v4c0 4-2.6 6.9-6 8.3-3.4-1.4-6-4.3-6-8.3v-4l6-2.3z"/>',
    "alert-triangle": (
        '<path d="M8 2.2l6.8 11.6H1.2L8 2.2z"/>'
        '<line x1="8" y1="6.6" x2="8" y2="9.6"/>'
        '<circle cx="8" cy="11.6" r="0.55" fill="currentColor" stroke="none"/>'
    ),
    "search": '<circle cx="6.5" cy="6.5" r="4.3"/><line x1="9.8" y1="9.8" x2="14.2" y2="14.2"/>',
    "network": (
        '<circle cx="3" cy="3.2" r="1.8"/><circle cx="13" cy="3.2" r="1.8"/><circle cx="8" cy="13" r="1.8"/>'
        '<line x1="4.5" y1="4.4" x2="6.8" y2="11"/><line x1="11.5" y1="4.4" x2="9.2" y2="11"/>'
    ),
    "activity": '<polyline points="1,8.5 4.5,8.5 6,3.5 9.5,13.5 11,8.5 15,8.5"/>',
    "check-circle": '<circle cx="8" cy="8" r="6.3"/><polyline points="5,8.2 7.1,10.3 11,5.9"/>',
    "alert-circle": (
        '<circle cx="8" cy="8" r="6.3"/><line x1="8" y1="4.8" x2="8" y2="8.6"/>'
        '<circle cx="8" cy="11" r="0.55" fill="currentColor" stroke="none"/>'
    ),
    "info": (
        '<circle cx="8" cy="8" r="6.3"/><line x1="8" y1="7.1" x2="8" y2="11.2"/>'
        '<circle cx="8" cy="4.9" r="0.55" fill="currentColor" stroke="none"/>'
    ),
    "refresh": '<path d="M13.6 8a5.6 5.6 0 1 1-1.7-4"/><polyline points="13.6,2.6 13.6,5.8 10.4,5.8"/>',
    "dot": '<circle cx="8" cy="8" r="4" fill="currentColor" stroke="none"/>',
}


def svg(name: str, size: int = 16, stroke_width: float = 1.7) -> str:
    body = _ICONS.get(name, "")
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 16 16" fill="none" '
        f'stroke="currentColor" stroke-width="{stroke_width}" stroke-linecap="round" '
        f'stroke-linejoin="round" xmlns="http://www.w3.org/2000/svg" '
        f'style="vertical-align:-3px;flex-shrink:0;">{body}</svg>'
    )
