from .app_factory import create_app

app = create_app()

if __name__ == "__main__":
    # For local dev only; use gunicorn in production
    import os
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8000"))
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host=host, port=port, debug=debug)
