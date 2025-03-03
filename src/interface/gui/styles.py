"""A module for styles constants to be used with other GUI modules.
    Elements: - window geometry,
              - Application title,
              - padding,
              - Entry boxes and button width,
              - Fonts,
              - Colours,
              - Corner radius.  
"""
# Window Properties
WINDOW_GEOMETRY = {
    "login": "400x600",
    "main": "800x600"
}
APP_TITLE = "Vault of Secrets"

# Spacing & Layout
PADDING = {
    "small": 5,
    "medium": 10,
    "large": 20
}
ENTRY_WIDTH = 200
BUTTON_WIDTH = 120

# Fonts
FONTS = {
    "header": ("Helvetica", 16, "bold"),
    "normal": ("Helvetica", 12),
    "small": ("Helvetica", 10)
}

# Colors & Themes
COLORS = {
    "dark": {
        "bg": "#2b2b2b",
        "fg": "#ffffff",
        "button": "#3b3b3b",
        "hover": "#4b4b4b",
        "entry": "#3b3b3b",
        "error": "#ff4444"
    },
    "light": {
        "bg": "#f0f0f0",
        "fg": "#000000",
        "button": "#e0e0e0",
        "hover": "#d0d0d0",
        "entry": "#ffffff",
        "error": "#ff0000"
    }
}

# Widget Properties
CORNER_RADIUS = {
    "tab": 10,
    "button": 8,
    "entry": 5
}