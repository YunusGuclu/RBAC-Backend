# accounts/apps.py
from django.apps import AppConfig


class AccountsConfig(AppConfig):
    name = "accounts"
    verbose_name = "Accounts"

    def ready(self):
        # signals modülünü import ederek bağlıyoruz (post_migrate içinde default admin oluşturacak)
        try:
            import accounts.signals  
        except Exception:
            # ready sırasında hata olursa loglayabilirsin; ama import etmeye çalışıyoruz
            pass
