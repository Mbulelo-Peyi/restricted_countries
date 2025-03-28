from django.http import HttpResponseForbidden
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import caches
from restricted_countries.utils import get_ip_address
from restricted_countries import settings
from django.contrib.gis.geoip2 import GeoIP2, GeoIP2Exception
import logging
import ipaddress

logger = logging.getLogger("restricted_countries")
cache = caches["default"]  # Use Memcached

class RestrictedCountriesMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Allow access for staff/admin users
        if hasattr(request, "user") and request.user.is_authenticated:
            if request.user.is_staff or request.user.is_superuser:
                return None  

        ip = get_ip_address(request)
        if not ip or self.is_private_ip(ip):
            return None  # Allow private/local IPs

        cache_key = f"geoip_country_{ip}"
        iso_code = cache.get(cache_key)  # Fetch from Memcached

        if iso_code is None:
            try:
                geo = GeoIP2()
                country = geo.country(ip)
                iso_code = country.get("country_code")
                cache.set(cache_key, iso_code, timeout=86400)  # Cache for 24 hours
            except (GeoIP2Exception, ValueError) as e:
                logger.error(f"GeoIP lookup failed for IP {ip}: {e}")
                return None  

        config = settings.get_config()
        if iso_code in config.get("COUNTRIES", []):
            return HttpResponseForbidden(config.get("FORBIDDEN_MSG", "Access forbidden."))

        return None  

    @staticmethod
    def is_private_ip(ip):
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False  
