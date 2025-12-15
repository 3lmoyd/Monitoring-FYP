import os, sys, subprocess, shutil
from pathlib import Path

# ---- CONFIG you can tweak ----
MODULE_NAME = "monitoringAgent"   # your Flask module filename (without .py)
APP_OBJECT  = "app"               # Flask app variable inside the module
PORT        = "8000"

# ---- Paths (auto relative to this file) ----
ROOT   = Path(__file__).parent.resolve()
FRONT  = ROOT / "frontend"        # expects package.json here if you have a React app
STATIC = ROOT / "server" / "static"  # optional; change to ROOT/"static" if your Flask serves from ./static

def msg(s): print(f"[run_all] {s}")

def ensure_frontend_built():
    """Build React only if frontend exists AND npm is available; otherwise skip gracefully."""
    pkg = FRONT / "package.json"
    if not pkg.exists():
        msg("No frontend/package.json found. Skipping frontend build.")
        return

    if shutil.which("npm") is None:
        msg("npm not found in PATH. Skipping frontend build. (Install Node.js LTS to enable this.)")
        return

    # Install deps if needed
    node_modules = FRONT / "node_modules"
    try:
        if not node_modules.exists():
            msg("node_modules missing -> running: npm ci")
            subprocess.check_call(["npm", "ci"], cwd=str(FRONT))
        # Build
        msg("Building frontend: npm run build")
        subprocess.check_call(["npm", "run", "build"], cwd=str(FRONT))
        msg("Frontend build complete.")
    except FileNotFoundError as e:
        msg(f"Build failed: command not found ({e}). Skipping frontend build.")
    except subprocess.CalledProcessError as e:
        msg(f"Build failed with exit code {e.returncode}. Check npm logs. Skipping frontend build.")

def serve_waitress():
    """Start the Flask app via Waitress."""
    # Make Python find your module in this folder
    sys.path.insert(0, str(ROOT))
    try:
        mod = __import__(MODULE_NAME)
        app = getattr(mod, APP_OBJECT)
    except Exception as e:
        msg(f"Could not import {MODULE_NAME}:{APP_OBJECT} -> {e}")
        msg("Make sure your monitoringAgent.py has: app = Flask(__name__)")
        sys.exit(1)

    from waitress import serve
    msg(f"Starting Flask+Waitress at http://0.0.0.0:{PORT}")
    serve(app, listen=f"0.0.0.0:{PORT}")

def main():
    ensure_frontend_built()
    serve_waitress()

if __name__ == "__main__":
    main()
