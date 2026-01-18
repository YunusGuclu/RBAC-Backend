from rest_framework.permissions import BasePermission

class IsAdminRole(BasePermission):
    message = "Sadece admin rolü erişebilir."

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not (user and user.is_authenticated):
            return False
       
        try:
            return user.has_role("admin")
        except Exception:
            return False


class HasFunctionPermission(BasePermission):
    message = "Bu işlemi yapma yetkiniz yok."

    def has_permission(self, request, view):
        user = getattr(request, "user", None)
        if not (user and user.is_authenticated):
            return False

        required_function = getattr(view, "required_function", None)
        required_module = getattr(view, "required_module", None)

        # Eğer hiçbir requirement yoksa izin ver
        if not required_function and not required_module:
            return True

        if required_module and required_function:
            return user.has_function_on_module(required_function, required_module)

        if required_function:
            return user.has_function(required_function)

        return False
