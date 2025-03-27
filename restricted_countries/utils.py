from ipware.ip import get_client_ip

def get_ip_address(request):
    ip_address, _ = get_client_ip(request)
    if not ip_address:  # Fallback method if ipware fails
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip_address = x_forwarded_for.split(',')[0]
        else:
            ip_address = request.META.get('REMOTE_ADDR', None)
    return ip_address
