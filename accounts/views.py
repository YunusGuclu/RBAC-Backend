from django.contrib.auth import get_user_model
from django.conf import settings
from rest_framework import permissions, status, generics
from rest_framework.response import Response
from rest_framework.exceptions import PermissionDenied
from rest_framework.views import APIView

from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken

from django.db import IntegrityError

from .serializers import (
    RegisterSerializer, UserSerializer, LogoutSerializer,
    RoleSerializer, ModuleSerializer, FunctionSerializer,
    FunctionModuleConnectionSerializer, RoleFunctionModuleConnectionSerializer,
    RoleUserConnectionSerializer,EmptySerializer,
)

from .permissions import IsAdminRole

from .models import (
    Role, Module, Function, FunctionModuleConnection,
    RoleFunctionModuleConnection, RoleUserConnection
)
from drf_spectacular.utils import extend_schema, extend_schema_view
import logging

User = get_user_model()

logger = logging.getLogger(__name__)


if getattr(settings, "ADMIN_UI_ALLOW_ANON_OPERATIONS", False):
    ADMIN_API_PERMISSIONS = [permissions.AllowAny]
else:
    ADMIN_API_PERMISSIONS = [permissions.IsAuthenticated, IsAdminRole]


# --- Auth serializers/views kept ---
class UserLoginSerializer(TokenObtainPairSerializer):
    def validate(self, attrs):
        """
        Normal kullanıcı ve admin aynı /auth/login/ endpoint'ini kullanacak.
        Burada sadece token üretilip user döndürülür.
        """
        data = super().validate(attrs)
        u = self.user
        data["user"] = UserSerializer(u).data
        return data

    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["email"] = getattr(user, "email", None)
        return token


class UserLoginView(TokenObtainPairView):
    permission_classes = [permissions.AllowAny]
    serializer_class = UserLoginSerializer


class MyTokenRefreshView(TokenRefreshView):
    permission_classes = [permissions.AllowAny]


class RegisterView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]
    serializer_class = RegisterSerializer
    queryset = User.objects.all()

    def post(self, request, *args, **kwargs):
        s = self.get_serializer(data=request.data)
        s.is_valid(raise_exception=True)
        user = s.save()
        refresh = RefreshToken.for_user(user)
        data = {
            "user": UserSerializer(user).data,
            "access": str(refresh.access_token),
            "refresh": str(refresh),
        }
        return Response(data, status=status.HTTP_201_CREATED)


@extend_schema(responses=UserSerializer)
class MeView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserSerializer

    def get(self, request):
        return Response(UserSerializer(request.user).data)


@extend_schema(request=LogoutSerializer, responses={205: None})
class LogoutView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = LogoutSerializer

    def post(self, request):
        refresh_str = request.data.get("refresh")
        if not refresh_str:
            return Response({"detail": "refresh gerekli"}, status=400)
        try:
            rt = RefreshToken(refresh_str)
        except (TokenError, InvalidToken) as e:
            return Response({"detail": "Geçersiz refresh", "error": str(e)}, status=400)

        token_user_id = str(rt.payload.get("user_id"))
        if token_user_id != str(request.user.id):
            raise PermissionDenied("Bu refresh size ait değil.")

        jti = rt.payload.get("jti")
        try:
            o = OutstandingToken.objects.get(jti=jti)
        except OutstandingToken.DoesNotExist:

            try:
                rt.blacklist()
            except TokenError as te:
                logger.warning("RefreshToken.blacklist() failed (TokenError): %s", te)
            except AttributeError as ae:
                logger.warning("RefreshToken.blacklist() not available or failed (AttributeError): %s", ae)
            except Exception as exc:
                logger.exception("Unexpected error while blacklisting refresh token (jti=%s): %s", jti, exc)
        else:
            BlacklistedToken.objects.get_or_create(token=o)

        return Response(status=status.HTTP_205_RESET_CONTENT)


@extend_schema(request=None, responses={205: None})
class LogoutAllView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        outs = OutstandingToken.objects.filter(user=request.user).only("id")
        BlacklistedToken.objects.bulk_create(
            [BlacklistedToken(token=o) for o in outs],
            ignore_conflicts=True,
        )
        return Response(status=status.HTTP_205_RESET_CONTENT)



@extend_schema_view(
    get=extend_schema(operation_id="v1_users_list", responses={200: UserSerializer(many=True)})
)
class UserListView(APIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = UserSerializer

    def get(self, request, *args, **kwargs):
        users = User.objects.all().order_by("-id")
        out = []
        for u in users:
            data = UserSerializer(u).data
            roles = RoleUserConnection.objects.filter(user=u).select_related("role").values_list("role__role_name", flat=True)
            data["roles"] = list(roles)
            out.append(data)
        return Response(out)


@extend_schema_view(
    get=extend_schema(operation_id="v1_users_retrieve", responses={200: UserSerializer}),
    delete=extend_schema(operation_id="v1_users_delete", responses={204: None}),
)
class UserDetailView(APIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = UserSerializer

    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            return None

    def get(self, request, pk, *args, **kwargs):
        u = self.get_object(pk)
        if not u:
            return Response({"detail": "Kullanıcı bulunamadı"}, status=status.HTTP_404_NOT_FOUND)
        data = UserSerializer(u).data
        roles = RoleUserConnection.objects.filter(user=u).select_related("role").values_list("role__role_name", flat=True)
        data["roles"] = list(roles)
        return Response(data)

    def delete(self, request, pk, *args, **kwargs):
        u = self.get_object(pk)
        if not u:
            return Response({"detail": "Kullanıcı bulunamadı"}, status=status.HTTP_404_NOT_FOUND)
        u.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


# --- Admin CRUD endpoints ---
class RoleListCreateView(generics.ListCreateAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = RoleSerializer
    queryset = Role.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
        except IntegrityError:
            return Response({"detail": "Bu rol zaten mevcut veya duplicate veri."}, status=409)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class RoleDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = RoleSerializer
    queryset = Role.objects.all()
    lookup_field = "role_id"


class ModuleListCreateView(generics.ListCreateAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = ModuleSerializer
    queryset = Module.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
        except IntegrityError:
            return Response({"detail": "Bu modül zaten mevcut veya duplicate veri."}, status=409)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class ModuleDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = ModuleSerializer
    queryset = Module.objects.all()
    lookup_field = "mod_id"


class FunctionListCreateView(generics.ListCreateAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = FunctionSerializer
    queryset = Function.objects.all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
        except IntegrityError:
            return Response({"detail": "Bu fonksiyon zaten mevcut veya duplicate veri."}, status=409)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class FunctionDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = FunctionSerializer
    queryset = Function.objects.all()
    lookup_field = "func_id"


class FMCListCreateView(generics.ListCreateAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = FunctionModuleConnectionSerializer
    queryset = FunctionModuleConnection.objects.select_related("module", "function").all().order_by("fmc_id")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
        except IntegrityError:
            return Response({"detail": "Bu modül-fonksiyon bağlantısı zaten mevcut."}, status=409)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class FMCDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = FunctionModuleConnectionSerializer
    queryset = FunctionModuleConnection.objects.select_related("module", "function").all()
    lookup_field = "fmc_id"


class RFMCListCreateView(generics.ListCreateAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = RoleFunctionModuleConnectionSerializer
    queryset = RoleFunctionModuleConnection.objects.select_related("role", "fmc__module", "fmc__function").all().order_by("rfmc_id")

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
        except IntegrityError:
            return Response({"detail": "Bu rol-fmc bağlantısı zaten mevcut."}, status=409)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class RFMCDetailView(generics.RetrieveUpdateDestroyAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = RoleFunctionModuleConnectionSerializer
    queryset = RoleFunctionModuleConnection.objects.select_related("role", "fmc__module", "fmc__function").all()
    lookup_field = "rfmc_id"


class RoleUserListCreateView(generics.ListCreateAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = RoleUserConnectionSerializer
    queryset = RoleUserConnection.objects.select_related("user", "role").all()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            self.perform_create(serializer)
        except IntegrityError:
            return Response({"detail": "Bu kullanıcı-rol ilişkisi zaten mevcut."}, status=409)
        headers = self.get_success_headers(serializer.data)
        return Response(serializer.data, status=status.HTTP_201_CREATED, headers=headers)


class RoleUserDetailView(generics.RetrieveDestroyAPIView):
    permission_classes = ADMIN_API_PERMISSIONS
    serializer_class = RoleUserConnectionSerializer
    queryset = RoleUserConnection.objects.select_related("user", "role").all()
    lookup_field = "ruc_id"



