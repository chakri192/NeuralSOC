"""
Strict SOC UI Design Tokens.
Enforces a calm, readable, high-contrast dark mode optimized for triage under pressure.
"""

COLORS = {
    "bg_main": "#1e1e24",       # Deep neutral charcoal
    "bg_surface": "#2b2b36",    # Slightly lighter panel
    "text_primary": "#f8f9fa",  # High-contrast off-white
    "text_secondary": "#a0aab2",# Muted gray-blue
    "accent": "#00bcd4",        # Restrained cool cyan
    
    # Severity & Status (Used sparingly)
    "critical": "#d32f2f",      # Red
    "high": "#f57c00",          # Orange
    "medium": "#fbc02d",        # Yellow
    "low": "#546e7a",           # Gray/Blue
    "healthy": "#388e3c",       # Green
    "degraded": "#fbc02d",
    "offline": "#d32f2f"
}

SPACING = {
    "xs": "4px",
    "sm": "8px",
    "md": "16px",
    "lg": "24px",
    "xl": "32px"
}

RADII = {
    "card": "12px",
    "badge": "4px",
    "button": "8px"
}

FONTS = {
    "mono": "'JetBrains Mono', 'Fira Code', monospace",
    "ui": "'Inter', 'Segoe UI', system-ui, sans-serif"
}
