from __future__ import annotations
from typing import Iterable

from django.db import models
from django.db.models import UniqueConstraint
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin


# -----------------------
# User manager
# -----------------------
class UserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email zorunludur")
        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", True)
        user = self.model(email=email, **extra_fields)
        if password:
            user.set_password(password)
        else:
            user.set_unusable_password()
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_active", True)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser için is_staff=True olmalı.")

        # create_user çağrısı; burada is_superuser flag'i set etmiyoruz
        user = self.create_user(email, password, **extra_fields)

        return user

# -----------------------
# User
# -----------------------
class User(AbstractBaseUser, PermissionsMixin):

    id = models.BigAutoField(primary_key=True, db_column="user_id")
    email = models.EmailField(unique=True, max_length=254, db_column="user_email")
    user_username = models.CharField(max_length=150, blank=True, null=True, db_column="user_username")
    first_name = models.CharField(max_length=150, blank=True, db_column="user_firstname")
    last_name = models.CharField(max_length=150, blank=True, db_column="user_lastname")

    is_active = models.BooleanField(default=True, db_column="user_is_active")
    is_staff = models.BooleanField(default=False, db_column="user_is_staff")

    date_joined = models.DateTimeField(auto_now_add=True, db_column="user_date_joined")
    user_createtime = models.DateTimeField(auto_now_add=True, null=True, db_column="user_createtime")
    user_detail = models.TextField(blank=True, default="", db_column="user_detail")

    objects = UserManager()

    USERNAME_FIELD = "email"
    REQUIRED_FIELDS: list[str] = []

    class Meta:
        db_table = "user_user"
        verbose_name = "Kullanıcı"
        verbose_name_plural = "Kullanıcılar"
        indexes = [
            models.Index(fields=["email"], name="user_user_email_idx"),
            models.Index(fields=["user_username"], name="user_user_username_idx"),
        ]

    def __str__(self):
        return self.email

    def get_full_name(self):
        return f"{(self.first_name or '').strip()} {(self.last_name or '').strip()}".strip()

    def get_short_name(self):
        return self.first_name or self.user_username or self.email

    # --------------------
    # Role / permission helpers (yeni schema ile çalışır)
    # --------------------
    def get_roles(self) -> Iterable["Role"]:
        """Kullanıcının rolleri (RoleUserConnection üzerinden)."""
        from .models import Role, RoleUserConnection
        role_ids = RoleUserConnection.objects.filter(user_id=self.pk).values_list("role_id", flat=True)
        return Role.objects.filter(role_id__in=role_ids)

    def has_role(self, role_name: str) -> bool:
        return self.get_roles().filter(role_name=role_name).exists()

    def get_functionmodule_connections_for_roles(self):
        from .models import RoleFunctionModuleConnection, RoleUserConnection
        role_ids = RoleUserConnection.objects.filter(user_id=self.pk).values_list("role_id", flat=True)
        rfmc_ids = RoleFunctionModuleConnection.objects.filter(role_id__in=role_ids).values_list("fmc_id", flat=True)
        from .models import FunctionModuleConnection
        return FunctionModuleConnection.objects.filter(fmc_id__in=rfmc_ids).distinct()

    def has_function_on_module(self, function_name: str, module_name: str) -> bool:
        from .models import RoleUserConnection, RoleFunctionModuleConnection
        role_ids = RoleUserConnection.objects.filter(user_id=self.pk).values_list("role_id", flat=True)
        return RoleFunctionModuleConnection.objects.filter(
            role_id__in=role_ids,
            fmc__function__func_name=function_name,
            fmc__module__mod_name=module_name,
        ).exists()

    def has_function(self, function_name: str) -> bool:
        from .models import RoleUserConnection, RoleFunctionModuleConnection
        role_ids = RoleUserConnection.objects.filter(user_id=self.pk).values_list("role_id", flat=True)
        return RoleFunctionModuleConnection.objects.filter(
            role_id__in=role_ids,
            fmc__function__func_name=function_name,
        ).exists()


# ------------------------------
# Role / Module / Function modelleri
# ------------------------------
class Role(models.Model):
    role_id = models.BigAutoField(primary_key=True)
    role_name = models.CharField(max_length=255, unique=True)
    role_detail = models.TextField(blank=True, default="")
    role_flag_delete = models.BooleanField(default=False)

    class Meta:
        db_table = "role_role"
        verbose_name = "Role"
        verbose_name_plural = "Roles"
        constraints = [
            UniqueConstraint(fields=["role_name"], name="unique_role_role_name"),
        ]

    def __str__(self):
        return self.role_name


class Module(models.Model):
    mod_id = models.BigAutoField(primary_key=True)
    mod_name = models.CharField(max_length=255, unique=True)
    mod_detail = models.TextField(blank=True, default="")

    class Meta:
        db_table = "module_lookup"
        verbose_name = "Module"
        verbose_name_plural = "Modules"
        constraints = [
            UniqueConstraint(fields=["mod_name"], name="unique_module_mod_name"),
        ]

    def __str__(self):
        return self.mod_name


class Function(models.Model):
    func_id = models.BigAutoField(primary_key=True)
    func_name = models.CharField(max_length=255, unique=True)
    func_detail = models.TextField(blank=True, default="")

    class Meta:
        db_table = "function_lookup"
        verbose_name = "Function"
        verbose_name_plural = "Functions"
        constraints = [
            UniqueConstraint(fields=["func_name"], name="unique_function_func_name"),
        ]

    def __str__(self):
        return self.func_name


# ------------------------------
# Function <-> Module (n-n) bağlantısı
# ------------------------------
class FunctionModuleConnection(models.Model):
    """
    Bir modülün hangi fonksiyonları içerdiğini tutan bağlantı tablosu
    (module <-> function) many-to-many via explicit table.
    """
    fmc_id = models.BigAutoField(primary_key=True)
    module = models.ForeignKey(
        Module,
        db_column="mod_id",
        on_delete=models.CASCADE,
        related_name="fmc_module_connections"
    )
    function = models.ForeignKey(
        Function,
        db_column="func_id",
        on_delete=models.CASCADE,
        related_name="fmc_function_connections"
    )

    class Meta:
        db_table = "function_module_connection"
        verbose_name = "FunctionModuleConnection"
        verbose_name_plural = "FunctionModuleConnections"
        constraints = [
            UniqueConstraint(fields=("module", "function"), name="unique_module_function_pair"),
        ]

    def __str__(self):
        return f"{self.module} :: {self.function}"


# ------------------------------
# Role <-> FunctionModuleConnection bağlantısı
# (rol hangi modülde hangi fonksiyona sahip)
# ------------------------------
class RoleFunctionModuleConnection(models.Model):
    rfmc_id = models.BigAutoField(primary_key=True)
    role = models.ForeignKey(
        Role,
        db_column="role_id",
        on_delete=models.CASCADE,
        related_name="rfmc_role_connections"
    )
    fmc = models.ForeignKey(
        FunctionModuleConnection,
        db_column="fmc_id",
        on_delete=models.CASCADE,
        related_name="rfmc_fmc_connections"
    )

    class Meta:
        db_table = "role_functionmoduleconnection"
        verbose_name = "RoleFunctionModuleConnection"
        verbose_name_plural = "RoleFunctionModuleConnections"
        constraints = [
            UniqueConstraint(fields=("role", "fmc"), name="unique_role_fmc_pair"),
        ]

    def __str__(self):
        return f"{self.role} -> {self.fmc}"


# ------------------------------
# Role <-> User bağlantısı
# ------------------------------
class RoleUserConnection(models.Model):
    ruc_id = models.BigAutoField(primary_key=True)
    user = models.ForeignKey(
        User,
        db_column="user_id",
        on_delete=models.CASCADE,
        related_name="roleuser_connections"
    )
    role = models.ForeignKey(
        Role,
        db_column="role_id",
        on_delete=models.CASCADE,
        related_name="userrole_connections"
    )

    class Meta:
        db_table = "role_userconnection"
        verbose_name = "RoleUserConnection"
        verbose_name_plural = "RoleUserConnections"
        constraints = [
            UniqueConstraint(fields=("user", "role"), name="unique_user_role_pair"),
        ]

    def __str__(self):
        return f"{self.user} -> {self.role}"
