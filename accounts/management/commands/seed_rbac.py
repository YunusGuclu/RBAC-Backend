# accounts/management/commands/seed_rbac.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import transaction, IntegrityError
import logging

from accounts.models import (
    Role, Module, Function,
    FunctionModuleConnection, RoleFunctionModuleConnection,
    RoleUserConnection
)

logger = logging.getLogger(__name__)
User = get_user_model()


class Command(BaseCommand):
    help = "Seed the DB with example users, roles, modules, functions and connections for RBAC testing."

    def handle(self, *args, **options):
        self.stdout.write(self.style.MIGRATE_HEADING("Starting RBAC seed..."))
        with transaction.atomic():
            # --- Functions ---
            func_names = ["create", "list", "update", "delete"]
            funcs = {}
            for name in func_names:
                f, _ = Function.objects.get_or_create(
                    func_name=name,
                    defaults={"func_detail": f"{name} action"}
                )
                funcs[name] = f
                self.stdout.write(self.style.SUCCESS(f"Function: {f.func_name} (id={f.func_id})"))

            # --- Modules ---
            modules_meta = [
                ("projects", "Project management module"),
                ("tasks", "Task management module"),
                ("reports", "Reporting module"),
            ]
            mods = {}
            for mod_name, mod_detail in modules_meta:
                m, _ = Module.objects.get_or_create(mod_name=mod_name, defaults={"mod_detail": mod_detail})
                mods[mod_name] = m
                self.stdout.write(self.style.SUCCESS(f"Module: {m.mod_name} (id={m.mod_id})"))

            # --- FunctionModuleConnections (all combinations) ---
            fmc_map = {}
            for m in mods.values():
                for f in funcs.values():
                    try:
                        fmc, created = FunctionModuleConnection.objects.get_or_create(
                            module=m,
                            function=f,
                        )
                    except IntegrityError as ie:
                        # race/constraint; try to fetch existing record
                        logger.warning("IntegrityError creating FMC %s -> %s: %s", m.mod_name, f.func_name, ie)
                        fmc = FunctionModuleConnection.objects.filter(module=m, function=f).first()
                        created = False
                    fmc_map[(m.mod_name, f.func_name)] = fmc
                    if created:
                        self.stdout.write(self.style.SUCCESS(f"Created FMC: {m.mod_name} -> {f.func_name} (id={fmc.fmc_id})"))
                    else:
                        self.stdout.write(self.style.NOTICE(f"FMC exists: {m.mod_name} -> {f.func_name} (id={fmc.fmc_id})"))

            # --- Roles ---
            role_names = ["admin", "manager", "editor", "viewer", "user"]
            roles = {}
            for rn in role_names:
                r, _ = Role.objects.get_or_create(role_name=rn, defaults={"role_detail": f"{rn} role"})
                roles[rn] = r
                self.stdout.write(self.style.SUCCESS(f"Role: {r.role_name} (id={r.role_id})"))

            # --- RoleFunctionModuleConnection (assign FMCs to roles) ---
            # admin -> all FMCs
            for fmc in fmc_map.values():
                try:
                    RoleFunctionModuleConnection.objects.get_or_create(role=roles["admin"], fmc=fmc)
                except IntegrityError as ie:
                    logger.warning("IntegrityError assigning admin -> fmc %s: %s", getattr(fmc, "fmc_id", "?"), ie)
            self.stdout.write(self.style.SUCCESS("Admin assigned to all FMC entries."))

            # manager -> projects & tasks : create, list, update
            manager_allowed = [
                ("projects", "create"), ("projects", "list"), ("projects", "update"),
                ("tasks", "create"), ("tasks", "list"), ("tasks", "update"),
            ]
            for modn, fn in manager_allowed:
                fmc = fmc_map.get((modn, fn))
                if fmc:
                    try:
                        RoleFunctionModuleConnection.objects.get_or_create(role=roles["manager"], fmc=fmc)
                    except IntegrityError as ie:
                        logger.warning("IntegrityError assigning manager -> %s/%s: %s", modn, fn, ie)

            # editor -> projects & tasks : create, list, update (but not delete)
            editor_allowed = [
                ("projects", "create"), ("projects", "list"), ("projects", "update"),
                ("tasks", "create"), ("tasks", "list"), ("tasks", "update"),
            ]
            for modn, fn in editor_allowed:
                fmc = fmc_map.get((modn, fn))
                if fmc:
                    try:
                        RoleFunctionModuleConnection.objects.get_or_create(role=roles["editor"], fmc=fmc)
                    except IntegrityError as ie:
                        logger.warning("IntegrityError assigning editor -> %s/%s: %s", modn, fn, ie)

            # viewer -> list only for all modules
            for modn in mods.keys():
                fmc = fmc_map.get((modn, "list"))
                if fmc:
                    try:
                        RoleFunctionModuleConnection.objects.get_or_create(role=roles["viewer"], fmc=fmc)
                    except IntegrityError as ie:
                        logger.warning("IntegrityError assigning viewer -> %s/list: %s", modn, ie)

            # user -> tasks: list & create
            for modn, fn in [("tasks", "list"), ("tasks", "create")]:
                fmc = fmc_map.get((modn, fn))
                if fmc:
                    try:
                        RoleFunctionModuleConnection.objects.get_or_create(role=roles["user"], fmc=fmc)
                    except IntegrityError as ie:
                        logger.warning("IntegrityError assigning user -> %s/%s: %s", modn, fn, ie)

            self.stdout.write(self.style.SUCCESS("Role -> FMC assignments created."))

            # --- Create example users and assign roles ---
            example_users = [
                {"email": "alice@example.com", "first_name": "Alice", "password": "TestPass123!", "role": "admin"},
                {"email": "bob@example.com", "first_name": "Bob", "password": "TestPass123!", "role": "manager"},
                {"email": "carol@example.com", "first_name": "Carol", "password": "TestPass123!", "role": "editor"},
                {"email": "dave@example.com", "first_name": "Dave", "password": "TestPass123!", "role": "viewer"},
                {"email": "eve@example.com", "first_name": "Eve", "password": "TestPass123!", "role": "user"},
            ]

            for uinfo in example_users:
                try:
                    user, created = User.objects.get_or_create(email=uinfo["email"], defaults={
                        "first_name": uinfo["first_name"],
                    })
                except IntegrityError as ie:
                    # race on user creation, try to fetch
                    logger.warning("IntegrityError creating user %s: %s", uinfo["email"], ie)
                    user = User.objects.filter(email=uinfo["email"]).first()
                    created = False

                if created:
                    user.set_password(uinfo["password"])
                    user.save()
                    self.stdout.write(self.style.SUCCESS(f"Created user {user.email} (id={user.id}) with password {uinfo['password']}"))
                else:
                    self.stdout.write(self.style.NOTICE(f"User exists: {user.email} (id={user.id})"))

                # attach role
                role_obj = roles.get(uinfo["role"])
                if role_obj:
                    try:
                        ruc, _ = RoleUserConnection.objects.get_or_create(user=user, role=role_obj)
                        self.stdout.write(self.style.SUCCESS(f"Assigned role {role_obj.role_name} to user {user.email}"))
                    except IntegrityError as ie:
                        logger.warning("IntegrityError assigning role %s to user %s: %s", role_obj.role_name, user.email, ie)

            # Optionally: if you have a superuser, ensure it has admin role entry too
            try:
                superusers = User.objects.filter(is_superuser=True)
                for su in superusers:
                    try:
                        r, _ = RoleUserConnection.objects.get_or_create(user=su, role=roles["admin"])
                        self.stdout.write(self.style.SUCCESS(f"Ensured superuser {su.email} has admin role link."))
                    except IntegrityError as ie:
                        logger.warning("IntegrityError ensuring superuser role for %s: %s", su.email, ie)
            except Exception as exc:
                # Log unexpected exceptions during the superuser handling so we don't silently swallow errors
                logger.exception("Unexpected error while ensuring superuser RBAC links: %s", exc)

        self.stdout.write(self.style.MIGRATE_LABEL("RBAC seed finished."))
