# -*- coding: utf-8 -*-
"""
    django-restricted_countries
    ~~~~~
    This Django middleware restricts access to your application based on the geographical location of the user’s IP address.\n 
    Using GeoIP2 and ipware, this middleware can block users from specific countries and return a customizable forbidden message.
"""

__version__ = '0.1.0'

default_app_config = 'restricted_countries.apps.RestrictedCountriesConfig'
