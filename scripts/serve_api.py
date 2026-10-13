"""Serve the FastAPI backend.

    python -m scripts.serve_api --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import argparse

from scripts.cli_common import banner, ok, settings_from_args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serve the IPI Test Range FastAPI backend.")
    parser.add_argument("--config", default=None)
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args(argv)

    from backend.services.config import get_settings

    settings = settings_from_args(args)
    host = args.host or settings.get("api.host", "127.0.0.1")
    port = args.port or int(settings.get("api.port", 8000))

    import uvicorn

    banner(f"Serving API on http://{host}:{port}")
    ok(f"OpenAPI docs: http://{host}:{port}/docs")
    ok(f"demo_mode   : {settings.demo_mode}")
    uvicorn.run(
        "backend.api.app:app",
        host=host,
        port=port,
        reload=args.reload or bool(settings.get("api.reload", False)),
        log_level="info",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())