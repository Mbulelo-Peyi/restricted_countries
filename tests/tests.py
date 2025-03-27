from django.test import TestCase, RequestFactory
from unittest.mock import patch, MagicMock
from django.http import HttpResponse, HttpResponseForbidden
from django.contrib.auth.models import AnonymousUser, User
from restricted_countries.middleware import RestrictedCountriesMiddleware
from restricted_countries import settings

class RestrictedCountriesMiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=HttpResponse("OK"))
        self.middleware = RestrictedCountriesMiddleware(self.get_response)

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_restricted_country(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        """Test that a user from a restricted country is blocked."""
        mock_get_client_ip.return_value = '123.45.67.89'
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }
        mock_geoip2.return_value.country.return_value = {
            'country_code': 'US',
            'country_name': 'United States'
        }

        request = self.factory.get('/')
        request.user = AnonymousUser()
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode(), "Access forbidden from your location.")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_allowed_country(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        """Test that a user from an allowed country is not blocked."""
        mock_get_client_ip.return_value = '123.45.67.89'
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }
        mock_geoip2.return_value.country.return_value = {
            'country_code': 'CA',
            'country_name': 'Canada'
        }

        request = self.factory.get('/')
        request.user = AnonymousUser()
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_geoip_exception_handling(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        """Test that users are allowed if GeoIP lookup fails."""
        mock_get_client_ip.return_value = '123.45.67.89'
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }
        mock_geoip2.side_effect = Exception("GeoIP2 error")

        request = self.factory.get('/')
        request.user = AnonymousUser()
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.settings.get_config')
    def test_missing_ip(self, mock_get_config, mock_get_client_ip):
        """Test that requests with no IP address are allowed."""
        mock_get_client_ip.return_value = None
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }

        request = self.factory.get('/')
        request.user = AnonymousUser()
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_admin_bypass(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        """Test that staff and superusers are not blocked."""
        mock_get_client_ip.return_value = '123.45.67.89'
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }
        mock_geoip2.return_value.country.return_value = {
            'country_code': 'US',
            'country_name': 'United States'
        }

        request = self.factory.get('/')
        request.user = User(is_staff=True)  # Staff user
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

        request.user = User(is_superuser=True)  # Superuser
        response = self.middleware(request)
        self.assertEqual(response.status_code, 200)

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_private_ip_bypass(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        """Test that private/local IPs are not blocked."""
        private_ips = ["127.0.0.1", "192.168.1.1", "10.0.0.1"]
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }

        for ip in private_ips:
            mock_get_client_ip.return_value = ip
            request = self.factory.get('/')
            request.user = AnonymousUser()
            response = self.middleware(request)
            self.assertEqual(response.status_code, 200)

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    @patch('django.core.cache.cache.get')
    @patch('django.core.cache.cache.set')
    def test_caching_geoip_lookup(self, mock_cache_set, mock_cache_get, mock_get_config, mock_geoip2, mock_get_client_ip):
        """Test that the middleware caches GeoIP lookups."""
        mock_get_client_ip.return_value = '123.45.67.89'
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }
        mock_geoip2.return_value.country.return_value = {
            'country_code': 'US',
            'country_name': 'United States'
        }

        # First request should store in cache
        mock_cache_get.return_value = None  # Simulate cache miss
        request = self.factory.get('/')
        request.user = AnonymousUser()
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
        mock_cache_set.assert_called_with("geoip_country_123.45.67.89", "US", timeout=86400)

        # Second request should use cached value
        mock_cache_get.return_value = "US"  # Simulate cache hit
        response = self.middleware(request)
        self.assertEqual(response.status_code, 403)
        mock_geoip2.assert_not_called()  # Ensure GeoIP lookup was skipped
