from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from django.contrib import admin
from django.views.static import serve
from django.urls import re_path
#from django.conf.urls import url
urlpatterns = [
    # Your URL patterns here
    path('admin/', admin.site.urls),
    path('', include('myapp.urls')),
    re_path(r'^robots.txt$', serve, {'path': 'robots.txt', 'document_root': settings.STATIC_ROOT}),
]


urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
