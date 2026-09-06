"""Design tokens for the dashboard: one matte-black dark palette, plus
severity and triage-status colors. Nothing else under dashboard/ should
hardcode a hex value -- import from here (CSS gets it via
css_variables(), Plotly charts via plotly_template()) so the whole app
can't drift out of sync the way it previously did (styles/app.css,
1_Overview.py, and 5_Network.py each hand-rolled their own, different
color scheme). Dark-only, deliberately: this app never offered a real
light theme (st.dataframe's canvas grid and native elements like <hr>
follow Streamlit's own theme, not this file, so a from a page-CSS-only
"light mode" always left those mismatched) -- see .streamlit/config.toml.
"""

SEVERITY_COLORS = {
    "critical": "#e5484d",
    "high": "#f5a524",
    "medium": "#f5d90a",
    "low": "#6b7785",
}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]

STATUS_COLORS = {
    "open": "#6b7785",
    "acknowledged": "#3b82f6",
    "confirmed": "#e5484d",
    "false_positive": "#8b93a1",
}
STATUS_LABELS = {
    "open": "Open",
    "acknowledged": "Acknowledged",
    "confirmed": "Confirmed",
    "false_positive": "False Positive",
}

FONTS = {
    "ui": "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
    "mono": "'JetBrains Mono', ui-monospace, 'SFMono-Regular', Menlo, monospace",
}

# A true matte black (neutral gray-black, no blue/navy tint) -- not #000
# (too harsh/OLED-stark for a screen people stare at for a full shift)
# and not a slate/navy charcoal either.
PALETTE = {
    "bg": "#0a0a0a",
    "surface": "#131313",
    "surface-raised": "#1a1a1a",
    "surface-hover": "#212121",
    "border": "#2a2a2a",
    "text": "#eeeeee",
    "text-muted": "#94948f",
    "accent": "#3b82f6",
    "accent-soft": "rgba(59, 130, 246, 0.14)",
    "shadow": "rgba(0, 0, 0, 0.5)",
}


def css_variables() -> str:
    """Renders the palette + shared tokens as a :root custom property
    block, injected once per render alongside styles/app.css."""
    lines = [f"  --{key}: {value};" for key, value in PALETTE.items()]
    lines += [f"  --font-{key}: {value};" for key, value in FONTS.items()]
    for severity, color in SEVERITY_COLORS.items():
        lines.append(f"  --severity-{severity}: {color};")
    for status, color in STATUS_COLORS.items():
        lines.append(f"  --status-{status.replace('_', '-')}: {color};")
    return ":root {\n" + "\n".join(lines) + "\n}"


def plotly_template() -> dict:
    """A minimal Plotly layout dict pulling from the same tokens as the
    CSS, passed as **kwargs to fig.update_layout() -- so a chart never
    looks like it belongs to a different app than the page around it."""
    return dict(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=PALETTE["text"], family=FONTS["ui"]),
        colorway=[
            SEVERITY_COLORS["critical"],
            SEVERITY_COLORS["high"],
            SEVERITY_COLORS["medium"],
            SEVERITY_COLORS["low"],
            PALETTE["accent"],
        ],
        margin=dict(l=0, r=0, t=10, b=0),
        legend=dict(font=dict(color=PALETTE["text-muted"])),
    )
