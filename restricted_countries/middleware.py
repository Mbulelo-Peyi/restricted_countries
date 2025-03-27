from django.http import HttpResponseForbidden
from restricted_countries.utils import get_ip_address
from restricted_countries import settings
from django.contrib.gis.geoip2 import GeoIP2
import logging

logger = logging.getLogger('restricted_countries')

class RestrictedCountriesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the client's IP address
        ip = get_ip_address(request)

        if ip:
            try:
                # Determine the country of the IP
                geo = GeoIP2()
                country = geo.country(ip)  # Returns a dict {'country_code': 'XX', 'country_name': 'Country'}
                iso_code = country.get('country_code')

                # Get settings only once
                config = settings.get_config()
                restricted_countries = config.get("COUNTRIES", [])
                msg = config.get("FORBIDDEN_MSG", "Access forbidden.")

                if iso_code in restricted_countries:
                    return HttpResponseForbidden(msg)
            except Exception as e:
                # Log the error with details
                logger.error(f"GeoIP lookup failed for IP {ip}: {e}")

        return self.get_response(request)
