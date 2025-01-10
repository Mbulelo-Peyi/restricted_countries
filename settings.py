''' Django restricted settings file '''
# -*- coding: utf-8 -*-
from django.conf import settings


DEFAULT_SETTINGS = {
    "COUNTRIES" : ['CN', 'RU', 'IR'],
    "FORBIDDEN_MSG" : "Access Denied"
}


def get_config():
    user_config = getattr(settings, 'DJANGO_RESTRICTED_COUNTRIES', {})

    config = DEFAULT_SETTINGS.copy()
    config.update(user_config)

    return config
