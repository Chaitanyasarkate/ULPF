import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent / "backend"
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from ulpf.api.__main__ import create_api_app, main

app = create_api_app()

if __name__ == "__main__":
    sys.exit(main())
