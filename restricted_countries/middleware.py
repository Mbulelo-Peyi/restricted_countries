from django.http import HttpResponseForbidden
from restricted_countries.utils import get_client_ip
from restricted_countries import settings
from django.contrib.gis.geoip2 import GeoIP2
import logging


logger = logging.getLogger('restricted_countries')

class RestricedCountriesMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get the client's IP address
        ip = get_client_ip(request)
        
        if ip:
            try:
                # Determine the country of the IP
                geo = GeoIP2()
                country = geo.country(ip)
                iso_code = country['country_code']
                
                # List of blocked countries (ISO Alpha-2 codes)
                restriced_countries = settings.get_config()["COUNTRIES"]
                msg = settings.get_config()["FORBIDDEN_MSG"]
                
                if iso_code in restriced_countries:
                    return HttpResponseForbidden(msg)
            except Exception:
                # Handle cases where the IP cannot be resolved
                logger.error(f"Unable to determine geolocation for {ip} the IP cannot be resolved")

        return self.get_response(request)
