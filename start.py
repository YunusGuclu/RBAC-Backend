#!/usr/bin/env python
"""
Start helper: loads .env, runs makemigrations, migrate, optionally creates default user
(without is_superuser flag), optionally assigns existing 'admin' role (does NOT auto-create),
then runs Django runserver. Aborts on migration errors.
"""
import os
import sys
import traceback
from pathlib import Path
import logging

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def main():
    PROJECT_DIR = Path(__file__).resolve().parent

    # load .env if present
    try:
        from dotenv import load_dotenv
        env_path = PROJECT_DIR / ".env"
        if env_path.exists():
            load_dotenv(env_path)
            logging.info(".env yüklendi")
    except Exception:
        logging.info("python-dotenv yok ya da yüklenemedi; ortamsal env'lere devam ediliyor")

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", os.getenv("DJANGO_SETTINGS_MODULE", "DjangoApi.settings"))

    # Django setup
    try:
        import django
        django.setup()
    except Exception:
        logging.error("Django kurulumu sırasında hata. DJANGO_SETTINGS_MODULE doğru mu? Detay:")
        traceback.print_exc()
        sys.exit(1)

    from django.conf import settings
    from django.core.management import call_command

    logging.info("Using settings module: %s", os.environ.get("DJANGO_SETTINGS_MODULE"))
    logging.info("DEBUG=%s", getattr(settings, "DEBUG", None))
    logging.info("Running makemigrations (this may create new migration files)...")

    # create migration files automatically (optional)
    try:
        call_command("makemigrations", "--noinput")
        logging.info("makemigrations tamamlandı (varsa yeni migration dosyaları üretildi).")
    except Exception:
        logging.error("makemigrations sırasında hata oluştu:")
        traceback.print_exc()
        logging.error("makemigrations hatası — script sonlandırılıyor. Önce bu hatayı düzeltin.")
        sys.exit(1)

    logging.info("Running migrations (this may take a moment)...")
    # Run migrations (abort on failure)
    try:
        call_command("migrate", "--noinput")
        logging.info("migrate başarılı.")
    except Exception:
        logging.error("Migrate sırasında hata oluştu:")
        traceback.print_exc()
        logging.error("Migrate başarısız — script sonlandırılıyor. Önce migrate hatasını düzeltin.")
        sys.exit(1)

    # Optional: DEFAULT admin user creation (do NOT set is_superuser)
    DEFAULT_ADMIN_EMAIL = os.getenv("DEFAULT_ADMIN_EMAIL") or os.getenv("DEFAULT_ADMIN_EMAIL".upper())
    DEFAULT_ADMIN_PASSWORD = os.getenv("DEFAULT_ADMIN_PASSWORD") or os.getenv("DEFAULT_ADMIN_PASSWORD".upper())

    if DEFAULT_ADMIN_EMAIL and DEFAULT_ADMIN_PASSWORD:
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()

            user_qs = User.objects.filter(email=DEFAULT_ADMIN_EMAIL)
            if user_qs.exists():
                admin_user = user_qs.first()
                logging.info("Default admin user already exists: %s (id=%s). Will not overwrite.", DEFAULT_ADMIN_EMAIL, admin_user.pk)
            else:
                try:
                    admin_user = User.objects.create_user(email=DEFAULT_ADMIN_EMAIL, password=DEFAULT_ADMIN_PASSWORD)
                except TypeError:
                    # fallback for weird create_user signatures
                    admin_user = User.objects.create_user(DEFAULT_ADMIN_EMAIL, DEFAULT_ADMIN_PASSWORD)
                logging.info("Created default admin user: %s (id=%s).", DEFAULT_ADMIN_EMAIL, admin_user.pk)

            # If Role model exists and there's already an 'admin' role, assign it.
            try:
                from accounts.models import Role, RoleUserConnection
                role_admin = Role.objects.filter(role_name__iexact="admin").first()
                if role_admin:
                    exists = RoleUserConnection.objects.filter(user=admin_user, role=role_admin).exists()
                    if not exists:
                        RoleUserConnection.objects.create(user=admin_user, role=role_admin)
                        logging.info("Existing 'admin' role found -> assigned to default user.")
                    else:
                        logging.info("Default user already has 'admin' role.")
                else:
                    logging.info("No 'admin' role found in Role table. Not creating it automatically.")
            except Exception:
                logging.info("accounts.models.Role not available or role assignment failed; skipping role assignment.")
        except Exception:
            logging.error("Default admin creation failed; traceback:")
            traceback.print_exc()
    else:
        logging.info("DEFAULT_ADMIN_EMAIL / DEFAULT_ADMIN_PASSWORD not set -> skipping default admin creation.")

    # Runserver: take runserver args from sys.argv if present, otherwise use env or defaults
    run_args = None
    if len(sys.argv) > 1 and "runserver" in sys.argv:
        idx = sys.argv.index("runserver")
        run_args = sys.argv[idx+1:]
    if not run_args:
        HOST = os.getenv("RUNSERVER_HOST", "127.0.0.1")
        PORT = os.getenv("RUNSERVER_PORT", "8000")
        run_args = [f"{HOST}:{PORT}"]

    logging.info("Starting Django development server via call_command('runserver', %s)", run_args)
    try:
        call_command("runserver", *run_args)
    except Exception:
        logging.error("runserver sırasında hata. Traceback:")
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
