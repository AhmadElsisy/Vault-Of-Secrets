# Security Constants
SECURITY = {
    'MIN_LENGTH': 12,
    'MAX_LENGTH': 50,
    'SESSION_DURATION': 300,  # 5 minutes
    'WARNING_TIME': 60,      # 1 minute warning
    'EXTENSION_TIME': 60     # 1 minute extension
}

# Database Constants
DATABASE = {
    'PATH': 'vault.db',
    'TABLE_NAMES': {
        'users': 'users',
        'passwords': 'passwords'
    }
}

# Session States
SESSION_STATES = {
    'ACTIVE': 'active',
    'WARNING': 'warning',
    'EXTENDED': 'extended',
    'EXPIRED': 'expired'
}

FILES = {
    'SESSION_FILE': 'session.csv',
    'SECURITY_LOG': 'security_events.log'
}