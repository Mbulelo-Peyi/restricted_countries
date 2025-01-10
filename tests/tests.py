from django.test import TestCase, RequestFactory
from unittest.mock import patch, MagicMock
from django.http import HttpResponse
from restricted_countries.middleware import RestricedCountriesMiddleware
from restricted_countries import settings

class RestricedCountriesMiddlewareTestCase(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.get_response = MagicMock(return_value=HttpResponse("OK"))
        self.middleware = RestricedCountriesMiddleware(self.get_response)

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_restricted_country(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        # Mock settings and IP resolution
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
        response = self.middleware(request)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.content.decode(), "Access forbidden from your location.")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_allowed_country(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        # Mock settings and IP resolution
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
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.middleware.GeoIP2')
    @patch('restricted_countries.settings.get_config')
    def test_geoip_exception_handling(self, mock_get_config, mock_geoip2, mock_get_client_ip):
        # Mock settings and IP resolution
        mock_get_client_ip.return_value = '123.45.67.89'
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }
        mock_geoip2.side_effect = Exception("GeoIP2 error")

        request = self.factory.get('/')
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")

    @patch('restricted_countries.utils.get_client_ip')
    @patch('restricted_countries.settings.get_config')
    def test_missing_ip(self, mock_get_config, mock_get_client_ip):
        # Mock settings and IP resolution
        mock_get_client_ip.return_value = None
        mock_get_config.return_value = {
            "COUNTRIES": ["US"],
            "FORBIDDEN_MSG": "Access forbidden from your location."
        }

        request = self.factory.get('/')
        response = self.middleware(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content.decode(), "OK")
