from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from restricted_countries.utils import get_ip_address
from restricted_countries import settings
from django.contrib.gis.geoip2 import GeoIP2, GeoIP2Exception
import logging
import ipaddress

logger = logging.getLogger("restricted_countries")

class RestrictedCountriesMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Get the client's IP address
        ip = get_ip_address(request)

        if not ip:
            return None  # Allow access if IP can't be determined

        # Exclude private/local IPs from GeoIP lookup
        if self.is_private_ip(ip):
            return None

        # Check if the IP’s country is already cached
        cache_key = f"geoip_country_{ip}"
        iso_code = cache.get(cache_key)

        if iso_code is None:
            try:
                # Determine the country of the IP
                geo = GeoIP2()
                country = geo.country(ip)  # Returns a dict {'country_code': 'XX', 'country_name': 'Country'}
                iso_code = country.get("country_code")

                # Cache the result to avoid repeated lookups (e.g., 24 hours)
                cache.set(cache_key, iso_code, timeout=86400)

            except (GeoIP2Exception, ValueError) as e:
                logger.error(f"GeoIP lookup failed for IP {ip}: {e}")
                return None  # Allow access if GeoIP lookup fails

        # Get restricted countries from settings
        config = settings.get_config()
        restricted_countries = config.get("COUNTRIES", [])
        forbidden_msg = config.get("FORBIDDEN_MSG", "Access forbidden.")

        # If the user's country is restricted, block access
        if iso_code in restricted_countries:
            return HttpResponseForbidden(forbidden_msg)

        return None  # Allow access

    @staticmethod
    def is_private_ip(ip):
        """Check if an IP is private/local (e.g., 127.0.0.1, 192.168.x.x)"""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False  # Handle invalid IP formats gracefully
