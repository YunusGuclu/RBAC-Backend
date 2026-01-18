# accounts/admin.py
from django.contrib import admin
from django.contrib.auth import get_user_model
from .models import (
    Role, Module, Function, FunctionModuleConnection,
    RoleFunctionModuleConnection, RoleUserConnection
)

User = get_user_model()

@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ("id", "email", "user_username", "date_joined")
    search_fields = ("email", "user_username", "first_name", "last_name")


admin.site.register(Role)
admin.site.register(Module)
admin.site.register(Function)
admin.site.register(FunctionModuleConnection)
admin.site.register(RoleFunctionModuleConnection)
admin.site.register(RoleUserConnection)
