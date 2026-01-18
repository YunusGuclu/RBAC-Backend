#!/usr/bin/env python
"""Customized manage.py that delegates runserver to start.py (if present)."""
import os
import sys
from pathlib import Path

def main():
    project_root = Path(__file__).resolve().parent

    # if runserver requested and start.py exists -> exec start.py (replaces current process)
    if len(sys.argv) > 1 and sys.argv[1] == "runserver":
        start_py = project_root / "start.py"
        if start_py.exists():
            os.execv(sys.executable, [sys.executable, str(start_py), *sys.argv[1:]])
        # otherwise fall back to normal manage.py behavior

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "DjangoApi.settings")
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and available on your PYTHONPATH environment variable?"
        ) from exc
    execute_from_command_line(sys.argv)

if __name__ == "__main__":
    main()
