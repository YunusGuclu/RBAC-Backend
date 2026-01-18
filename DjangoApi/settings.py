# DjangoApi/settings.py
from pathlib import Path
import os
from datetime import timedelta
from dotenv import load_dotenv

# --- Baz dizin ve .env ---
BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

# --- Temel ayarlar ---
SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
DEBUG = os.getenv("DEBUG", "1") in ("1", "true", "True")
ALLOWED_HOSTS = [h.strip() for h in os.getenv("ALLOWED_HOSTS", "127.0.0.1,localhost").split(",") if h.strip()]

INSTALLED_APPS = [
    # Django core
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django_extensions",

    # 3rd   party
    "rest_framework",
    "rest_framework_simplejwt",
    "rest_framework_simplejwt.token_blacklist",
    "corsheaders",
    "drf_spectacular",

    # our app (use apps config so ready() runs)
    "accounts.apps.AccountsConfig",
]

# Middleware sırası (CORS en üstlerde olmalı)
MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# URL/WSGI/ASGI
ROOT_URLCONF = "DjangoApi.urls"
WSGI_APPLICATION = "DjangoApi.wsgi.application"
ASGI_APPLICATION = "DjangoApi.asgi.application"

# Templates
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]



DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("DB_NAME", "django_api"),
        "USER": os.getenv("DB_USER", "django"),
        "PASSWORD": os.getenv("DB_PASSWORD", "Password123!"),
        "HOST": os.getenv("DB_HOST", "127.0.0.1"),
        "PORT": os.getenv("DB_PORT", "5432"),


    }
}




# Parola politikası
AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator", "OPTIONS": {"min_length": 8}},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

# Dil / Zaman
LANGUAGE_CODE = "tr"  # Django locale kodu 'tr' olmalı (tr-tr yerine).
TIME_ZONE = os.getenv("TIME_ZONE", "Europe/Istanbul")
USE_I18N = True
USE_TZ = True

# Statik dosyalar
STATIC_URL = "static/"
STATIC_ROOT = BASE_DIR / "staticfiles"  # prod’da collectstatic için
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Custom User
AUTH_USER_MODEL = "accounts.User"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": (
        # SessionAuthentication eklendi — superuser'in Django oturumuyla admin UI çalışsın
        "rest_framework.authentication.SessionAuthentication",
        "rest_framework_simplejwt.authentication.JWTAuthentication",
    ),
    "DEFAULT_PERMISSION_CLASSES": (
        "rest_framework.permissions.IsAuthenticated",
    ),
}
ADMIN_UI_ALLOW_ANON_OPERATIONS = True

from dotenv import load_dotenv
load_dotenv(BASE_DIR / ".env")

ADMIN_UI_ALLOW_ANON_OPERATIONS = os.getenv("ADMIN_UI_ALLOW_ANON_OPERATIONS", "0") in ("1", "true", "True")



# SimpleJWT
ACCESS_MIN = int(os.getenv("ACCESS_MIN", 60))
REFRESH_DAYS = int(os.getenv("REFRESH_DAYS", 7))
SIMPLE_JWT = {
    "ACCESS_TOKEN_LIFETIME": timedelta(minutes=ACCESS_MIN),
    "REFRESH_TOKEN_LIFETIME": timedelta(days=REFRESH_DAYS),
    "ROTATE_REFRESH_TOKENS": True,
    "BLACKLIST_AFTER_ROTATION": True,
    "UPDATE_LAST_LOGIN": True,
}

# CORS / CSRF (Vue Vite varsayılan portu 5173)
CORS_ALLOWED_ORIGINS = [
    o.strip() for o in os.getenv(
        "CORS_ALLOWED_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",") if o.strip()
]
CSRF_TRUSTED_ORIGINS = [
    o.strip() for o in os.getenv(
        "CSRF_TRUSTED_ORIGINS",
        "http://127.0.0.1:5173,http://localhost:5173"
    ).split(",") if o.strip()
]
CORS_ALLOW_CREDENTIALS = True  # cookie tabanlı auth düşünebilirsin

REST_FRAMEWORK["DEFAULT_SCHEMA_CLASS"] = "drf_spectacular.openapi.AutoSchema"

# --- drf-spectacular OpenAPI / Swagger ayarları (daha okunur UI için) ---
SPECTACULAR_SETTINGS = {
    # Genel meta
    "TITLE": "DjangoApi — Accounts / RBAC API",
    "DESCRIPTION": (
        "Accounts & RBAC API. Kullanıcı, rol, modül, fonksiyon, "
        "modül↔fonksiyon (FMC) ve rol↔FMC (RFMC) yönetimi."
    ),
    "VERSION": "1.0.0",
    "CONTACT": {"name": "Backend Team", "email": "backend@example.com"},
    "LICENSE": {"name": "MIT"},

    # Küçük iyileştirmeler
    "SERVE_INCLUDE_SCHEMA": True,   # /api/schema/ JSON'ı sun
    # Request/response body'leri daha temiz bölümlere ayır (isteğe göre aç/kapa)
    "COMPONENT_SPLIT_REQUEST": True,
    # modeller büyükse listelenmesini engellemek için kullanılabilir (öneri)
    "DEFAULT_GENERATOR_CLASS": "drf_spectacular.generators.SchemaGenerator",

    # Güvenlik şemaları (JWT)
    "SECURITY": [{"bearerAuth": []}],
    "COMPONENTS": {
        "securitySchemes": {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
        }
    },

    # Diğer davranışlar
    "PREPROCESSING_HOOKS": [],
    "POSTPROCESSING_HOOKS": [],
}
DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL", None)
DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD", None)
# .env yüklendikten hemen sonra ekle
APP_NAME = os.getenv("APP_NAME", "DjangoApi")
# --- Loki + file logging (mevcut LOGGING'i bozmadan) ---
import os
import logging as _logging
from logging import Formatter

# ENV toggles
ENABLE_LOKI_LOGGING = os.getenv("ENABLE_LOKI_LOGGING", "0") in ("1", "true", "True")
base_loki = os.getenv("LOKI_URL", "http://localhost:3100").rstrip("/")
LOKI_PUSH_URL = os.getenv("LOKI_PUSH_URL", f"{base_loki}/loki/api/v1/push")
LOKI_AUTH_TOKEN = os.getenv("LOKI_AUTH_TOKEN", "")
try:
    LOKI_TIMEOUT = int(os.getenv("LOKI_TIMEOUT", 5))
except Exception:
    LOKI_TIMEOUT = 5

LOKI_JOB_NAME = os.getenv("LOKI_JOB_NAME", os.getenv("APP_NAME", "DjangoApi"))

# Ensure a logs dir and logfile exist and are writable
BASE_DIR = globals().get("BASE_DIR", os.getcwd())
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
FILE_LOG_PATH = os.path.join(LOG_DIR, "django.log")

# make sure file exists and permissive for dev (adjust for prod)
try:
    open(FILE_LOG_PATH, "a").close()
    os.chmod(FILE_LOG_PATH, 0o666)
except Exception:
    # izin/FS hatası olursa uygulamayı kırmamak için sessizce devam et
    pass

# Safely get existing LOGGING
LOGGING = globals().get("LOGGING")
if not isinstance(LOGGING, dict):
    LOGGING = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "simple": {"format": "%(asctime)s %(levelname)s %(name)s: %(message)s"},
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "formatter": "simple"},
        },
        "root": {"level": "INFO", "handlers": ["console"]},
    }

# prepare handlers list we want everywhere
common_handlers = ["console", "file"]
if ENABLE_LOKI_LOGGING:
    common_handlers.append("loki")

# Add file handler (idempotent)
LOGGING.setdefault("handlers", {})
if "file" not in LOGGING["handlers"]:
    LOGGING["handlers"]["file"] = {
        "level": "INFO",
        "class": "logging.handlers.RotatingFileHandler",
        "filename": FILE_LOG_PATH,
        "maxBytes": 10 * 1024 * 1024,
        "backupCount": 3,
        "formatter": "simple",
        # 'encoding': 'utf-8' # istersen ekle
    }

# Add loki handler only if requested (idempotent)
if ENABLE_LOKI_LOGGING:
    try:
        if "loki" not in LOGGING["handlers"]:
            LOGGING["handlers"]["loki"] = {
                "level": "INFO",
                "class": "loki_proxy.handlers.LokiHandler",  # proje/virtualenv içinde olmalı
                "formatter": "simple",
                "url": LOKI_PUSH_URL,
                "token": LOKI_AUTH_TOKEN,
                "timeout": LOKI_TIMEOUT,
                "job": LOKI_JOB_NAME,
            }
    except Exception as e:
        _logging.getLogger().warning("Adding loki handler failed: %s", e)
        # disable loki if something went wrong
        try:
            LOGGING["handlers"].pop("loki", None)
            if "loki" in common_handlers:
                common_handlers.remove("loki")
        except Exception:
            pass

# ensure root handlers include our handlers (idempotent)
LOGGING.setdefault("root", {})
LOGGING["root"].setdefault("level", "INFO")
rh = LOGGING["root"].setdefault("handlers", [])
for h in common_handlers:
    if h not in rh:
        rh.append(h)

# make sure common Django loggers propagate to root or use same handlers
LOGGING.setdefault("loggers", {})
# Catch generic django logs (incl. runserver)
LOGGING["loggers"].setdefault("django", {"handlers": common_handlers, "level": "INFO", "propagate": True})
# runserver startup logs are often in django.server
LOGGING["loggers"].setdefault("django.server", {"handlers": common_handlers, "level": "INFO", "propagate": False})
# your app root logger (optional; ensures app logs go to same place)
LOGGING["loggers"].setdefault("", {"handlers": common_handlers, "level": "INFO", "propagate": True})
# -----------------------------------------------------------------------
