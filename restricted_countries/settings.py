''' Django restricted settings file '''
# -*- coding: utf-8 -*-
from django.conf import settings

DEFAULT_SETTINGS = {
    "COUNTRIES": ["ZA"],  # Blocked countries (ISO Alpha-2 codes)
    "FORBIDDEN_MSG": "Access Denied",
}

def get_config():
    user_config = getattr(settings, "DJANGO_RESTRICTED_COUNTRIES", {})

    # Ensure the custom settings are a dictionary
    if not isinstance(user_config, dict):
        raise TypeError("DJANGO_RESTRICTED_COUNTRIES must be a dictionary.")

    config = DEFAULT_SETTINGS.copy()  # Prevent modifying original defaults
    config.update(user_config)  # Merge user settings

    return config
