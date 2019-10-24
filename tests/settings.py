DEBUG = False

TIME_ZONE = "UTC"
LANGUAGE_CODE = "en-US"
USE_L10N = True
USE_TZ = True

SECRET_KEY = "dont-tell-eve"

ROOT_URLCONF = "tests.urls"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

INSTALLED_APPS = (
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.sites",
    "tests",
)

PASSWORD_HASHERS = ("django.contrib.auth.hashers.MD5PasswordHasher",)

JWT_LOGIN_URLS = ["/token-auth/"]
