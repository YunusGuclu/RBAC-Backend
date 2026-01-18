from typing import Optional, List
from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.tokens import RefreshToken, TokenError

from .models import (
    Role, Module, Function,
    FunctionModuleConnection, RoleFunctionModuleConnection, RoleUserConnection
)

User = get_user_model()


class UserSerializer(serializers.Serializer):
    """
    Model bağımlılığını azaltmak için ModelSerializer yerine manuel Serializer kullanalım.
    Böylece kullanıcının User modelindeki alan isimleri farklı olsa da çalışır.
    """
    id = serializers.IntegerField(source="pk")
    email = serializers.SerializerMethodField()
    user_username = serializers.SerializerMethodField()
    first_name = serializers.SerializerMethodField()
    last_name = serializers.SerializerMethodField()
    is_active = serializers.SerializerMethodField()
    is_staff = serializers.SerializerMethodField()
    date_joined = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    def get_email(self, obj) -> Optional[str]:
        for a in ("email", "user_email", "username", "user_username"):
            v = getattr(obj, a, None)
            if v is not None:
                return v
        return None

    def get_user_username(self, obj) -> Optional[str]:
        for a in ("user_username", "username", "user_name", "user", "email"):
            v = getattr(obj, a, None)
            if v is not None:
                return v
        return None

    def get_first_name(self, obj) -> str:
        return getattr(obj, "first_name", "") or ""

    def get_last_name(self, obj) -> str:
        return getattr(obj, "last_name", "") or ""

    def get_is_active(self, obj) -> bool:
        return bool(getattr(obj, "is_active", False))

    def get_is_staff(self, obj) -> bool:
        return bool(getattr(obj, "is_staff", False))

    def get_date_joined(self, obj) -> Optional[str]:
        dj = getattr(obj, "date_joined", None)
        if dj is None:
            return None
        try:
            return dj.isoformat()
        except Exception:
            return str(dj)

    def get_roles(self, obj) -> List[str]:
        qs = RoleUserConnection.objects.filter(user=obj).select_related("role").values_list("role__role_name", flat=True)
        return list(qs)


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password], style={"input_type": "password"})
    password2 = serializers.CharField(write_only=True, style={"input_type": "password"})

    class Meta:
        model = User
        # Keep allowed fields minimal; if your User model uses different fields, adapt here if needed.
        fields = ("email", "user_username", "first_name", "last_name", "password", "password2")

    def validate(self, attrs):
        if attrs.get("password") != attrs.get("password2"):
            raise serializers.ValidationError({"password": "Şifreler eşleşmiyor"})
        return attrs

    def create(self, validated_data):
        validated_data.pop("password2", None)
        password = validated_data.pop("password")
        user = User.objects.create_user(password=password, **validated_data)
        return user


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField(write_only=True)

    def validate(self, attrs):
        self.token = attrs["refresh"]
        return attrs

    def save(self, **kwargs):
        try:
            RefreshToken(self.token).blacklist()
        except TokenError:
            raise serializers.ValidationError({"refresh": "Geçersiz ya da daha önce iptal edilmiş token"})


# ----------------------------
# Admin-side serializers (FMC / RFMC / Role / Module / Function)
# ----------------------------
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Role
        fields = ("role_id", "role_name", "role_detail", "role_flag_delete")


class ModuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Module
        fields = ("mod_id", "mod_name", "mod_detail") 


class FunctionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Function
        fields = ("func_id", "func_name", "func_detail")


class FunctionModuleConnectionSerializer(serializers.ModelSerializer):
    # hem id hem okunabilir isimler döndürüyoruz
    module_name = serializers.CharField(source="module.mod_name", read_only=True)
    function_name = serializers.CharField(source="function.func_name", read_only=True)

    class Meta:
        model = FunctionModuleConnection
        fields = ("fmc_id", "module", "module_name", "function", "function_name")


class RoleFunctionModuleConnectionSerializer(serializers.ModelSerializer):
    # writable PK fields so DRF form shows selects
    role = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all())
    fmc = serializers.PrimaryKeyRelatedField(
        queryset=FunctionModuleConnection.objects.select_related("module", "function").all()
    )

    # readable helper fields (for nice responses)
    role_name = serializers.CharField(source="role.role_name", read_only=True)
    fmc_detail = FunctionModuleConnectionSerializer(source="fmc", read_only=True)
    fmc_module_name = serializers.CharField(source="fmc.module.mod_name", read_only=True)
    fmc_function_name = serializers.CharField(source="fmc.function.func_name", read_only=True)

    class Meta:
        model = RoleFunctionModuleConnection
        fields = (
            "rfmc_id",
            "role",             # writable PK (shows dropdown)
            "role_name",        # read-only name
            "fmc",              # writable PK (shows dropdown)
            "fmc_detail",       # nested read-only details
            "fmc_module_name",
            "fmc_function_name",
        )

class RoleUserConnectionSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)
    role_name = serializers.CharField(source="role.role_name", read_only=True)

    class Meta:
        model = RoleUserConnection
        fields = ("ruc_id", "user", "user_email", "role", "role_name")




class EmptySerializer(serializers.Serializer):
    pass