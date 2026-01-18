# accounts/urls.py
from django.urls import path

from .views import (
    RegisterView, MeView,
    UserLoginView, MyTokenRefreshView, LogoutView, LogoutAllView,
    RoleListCreateView, RoleDetailView,
    ModuleListCreateView, ModuleDetailView,
    FunctionListCreateView, FunctionDetailView,
    FMCListCreateView, FMCDetailView,
    RFMCListCreateView, RFMCDetailView,
    RoleUserListCreateView, RoleUserDetailView,
    UserListView, UserDetailView,
)

urlpatterns = [

    path("auth/register/", RegisterView.as_view(), name="register"),
    path("auth/login/", UserLoginView.as_view(), name="user_login"),
    path("auth/token/refresh/", MyTokenRefreshView.as_view(), name="token_refresh"),
    path("auth/logout/", LogoutView.as_view(), name="logout"),
    path("auth/logout/all/", LogoutAllView.as_view(), name="logout_all"),
    path("users/me/", MeView.as_view(), name="me"),

    path("users/", UserListView.as_view(), name="admin_users_list"),
    path("users/<int:pk>/", UserDetailView.as_view(), name="admin_user_detail"),

    path("roles/", RoleListCreateView.as_view(), name="roles_list_create"),
    path("roles/<int:role_id>/", RoleDetailView.as_view(), name="role_detail"),

    path("modules/", ModuleListCreateView.as_view(), name="modules_list_create"),
    path("modules/<int:mod_id>/", ModuleDetailView.as_view(), name="module_detail"),

    path("functions/", FunctionListCreateView.as_view(), name="functions_list_create"),
    path("functions/<int:func_id>/", FunctionDetailView.as_view(), name="function_detail"),

    path("function-modules/", FMCListCreateView.as_view(), name="fmc_list_create"),
    path("function-modules/<int:fmc_id>/", FMCDetailView.as_view(), name="fmc_detail"),

    path("role-function-modules/", RFMCListCreateView.as_view(), name="rfmc_list_create"),
    path("role-function-modules/<int:rfmc_id>/", RFMCDetailView.as_view(), name="rfmc_detail"),

    path("role-user/", RoleUserListCreateView.as_view(), name="roleuser_list_create"),
    path("role-user/<int:ruc_id>/", RoleUserDetailView.as_view(), name="roleuser_detail"),


]
