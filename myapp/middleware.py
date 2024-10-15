from django.http import HttpResponsePermanentRedirect

class RedirectToHttpsAndWwwMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        host = request.get_host()
        if not host.startswith('www.'):
            # Redirect non-www to www
            new_url = request.build_absolute_uri().replace(f"//{host}", f"//www.{host}")
            return HttpResponsePermanentRedirect(new_url)
        
        # Ensure HTTPS
        if not request.is_secure():
            secure_url = request.build_absolute_uri(request.get_full_path()).replace('http://', 'https://')
            return HttpResponsePermanentRedirect(secure_url)

        return self.get_response(request)