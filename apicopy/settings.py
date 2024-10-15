from pathlib import Path
import os
# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'django-insecure-on*@_=0aweac8^m$)v9(b8mgif-vgger65)0d5f18dm#n=yag7'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = ["*"]


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'myapp',
    'rest_framework',
    'compressor',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',
    'myapp.middleware.RedirectToHttpsAndWwwMiddleware',
]

STATICFILES_FINDERS = [
    'django.contrib.staticfiles.finders.FileSystemFinder',
    'django.contrib.staticfiles.finders.AppDirectoriesFinder',
    'compressor.finders.CompressorFinder',
]

STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

ROOT_URLCONF = 'apicopy.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'apicopy.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}



PAYVESSEL_BASE_URL = 'https://api.payvessel.com/api/external/request/customerReservedAccount/'
PAYVESSEL_SECRET_KEY = 'PVSECRET-IWPX3A0EIWWL94I8S5O7A76LHPREDAJTB2VFDBSG059LQ1FGGMJ94Q8EAK5OX7Z9'
PAYVESSEL_API_KEY = 'PVKEY-8UCVVQG9DZRDDKK0VGZQ4Y38RY7K9YAM'
BUSINESS_ID = "603921895BF548068EFC9B22A7BEF8A8"
# settings.py
PAYSTACK_SECRET_KEY = 'sk_live_af6b69939fce3375a3fcc147d29c0d3659699c21'
PAYSTACK_PUBLIC_KEY = 'pk_live_5fadf3b006945de22692358a244a5af7d638d2f9'


EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'mail.paystar.com.ng'  # Replace with your cPanel SMTP host
EMAIL_PORT = 465  # Use 465 for SSL or 587 for TLS
EMAIL_USE_SSL = True  # Use SSL if you're using port 465
EMAIL_USE_TLS = False  # Set to True if using port 587 instead of 465
EMAIL_HOST_USER = 'support@paystar.com.ng'  # Your cPanel email address
EMAIL_HOST_PASSWORD = 'olaniyi90FAC'  # The password for your cPanel email account
DEFAULT_FROM_EMAIL = 'support@paystar.com.ng'  # Default sender email



AUTHENTICATION_BACKENDS = [
    'myapp.backends.UsernameOrEmailBackend',  # Replace with the actual path to the custom backend
    'django.contrib.auth.backends.ModelBackend',
]


# Password validation
# https://docs.djangoproject.com/en/5.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.1/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATICFILES_DIRS = [
  os.path.join(BASE_DIR, "static/css"),
  os.path.join(BASE_DIR, "static/Js"),
  os.path.join(BASE_DIR, "static/css/nightmode")
  
]
MEDIA_URL = "media/"
MEDIA_ROOT = os.path.join(BASE_DIR, "media")

# Default primary key field type
# https://docs.djangoproject.com/en/5.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
