# accounts/management/commands/seed_initial_data.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.conf import settings

from accounts.models import Role, Module, Function, FunctionModuleConnection, RoleFunctionModuleConnection

User = get_user_model()


class Command(BaseCommand):
    help = "Seed initial roles/modules/functions for the project (idempotent)."

    def handle(self, *args, **options):
        # 1) ensure 'admin' and 'user' roles exist
        admin_role, _ = Role.objects.get_or_create(role_name="admin", defaults={"role_detail": "Sistem yöneticisi"})
        user_role, _ = Role.objects.get_or_create(role_name="user", defaults={"role_detail": "Normal kullanıcı"})

        # 2) sample modules and functions
        mod_users, _ = Module.objects.get_or_create(mod_name="users", defaults={"mod_detail": "Kullanıcı yönetimi"})
        mod_rbac, _ = Module.objects.get_or_create(mod_name="rbac", defaults={"mod_detail": "Yetki yönetimi"})

        fn_create, _ = Function.objects.get_or_create(func_name="create", defaults={"func_detail": "Create action"})
        fn_list, _ = Function.objects.get_or_create(func_name="list", defaults={"func_detail": "List action"})
        fn_update, _ = Function.objects.get_or_create(func_name="update", defaults={"func_detail": "Update action"})
        fn_delete, _ = Function.objects.get_or_create(func_name="delete", defaults={"func_detail": "Delete action"})

        # 3) connect functions <-> modules
        f1, _ = FunctionModuleConnection.objects.get_or_create(module=mod_users, function=fn_create)
        f2, _ = FunctionModuleConnection.objects.get_or_create(module=mod_users, function=fn_list)
        f3, _ = FunctionModuleConnection.objects.get_or_create(module=mod_rbac, function=fn_create)
        f4, _ = FunctionModuleConnection.objects.get_or_create(module=mod_rbac, function=fn_update)

        # 4) admin role gets all these function-module combos
        RoleFunctionModuleConnection.objects.get_or_create(role=admin_role, fmc=f1)
        RoleFunctionModuleConnection.objects.get_or_create(role=admin_role, fmc=f2)
        RoleFunctionModuleConnection.objects.get_or_create(role=admin_role, fmc=f3)
        RoleFunctionModuleConnection.objects.get_or_create(role=admin_role, fmc=f4)

        self.stdout.write(self.style.SUCCESS("Seed tamamlandı: roles/modules/functions ekli."))
        self.stdout.write("Hatırlatma: Süperuser için `python manage.py createsuperuser` çalıştır.")
