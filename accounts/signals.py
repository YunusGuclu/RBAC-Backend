# accounts/signals.py
from django.conf import settings
from django.db.models.signals import post_migrate
from django.dispatch import receiver
from django.contrib.auth import get_user_model

from .models import Role, RoleUserConnection

User = get_user_model()


@receiver(post_migrate)
def create_default_admin(sender, **kwargs):

    email = getattr(settings, "DEFAULT_ADMIN_EMAIL", None)
    password = getattr(settings, "DEFAULT_ADMIN_PASSWORD", None)

    if not email or not password:
        return  # env'de değer yoksa hiçbirşey yapma

    # eğer kullanıcı zaten varsa devam etme
    try:
        u = User.objects.filter(email=email).first()
    except Exception:
        # DB yoksa / migrate sırasında henüz tablo yoksa hata gelebilir
        return

    if u:
        # kullanıcı zaten varsa, rol atılmış mı kontrol et
        admin_role, _ = Role.objects.get_or_create(role_name="admin")
        if not RoleUserConnection.objects.filter(user=u, role=admin_role).exists():
            RoleUserConnection.objects.create(user=u, role=admin_role)
        # is_staff update et
        if not getattr(u, "is_staff", False):
            u.is_staff = True
            u.save(update_fields=["is_staff"])
        return

    # kullanıcı yoksa oluştur
    try:
        user = User.objects.create_user(email=email, password=password)
        # set is_staff True so the user can access admin UI if needed
        user.is_staff = True
        user.save(update_fields=["is_staff"])

        # rol oluştur / ata
        admin_role, _ = Role.objects.get_or_create(role_name="admin")
        RoleUserConnection.objects.create(user=user, role=admin_role)
    except Exception:
        # hata varsa sessiz geçer; production için log ekle
        return
