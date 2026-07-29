"""API documentation generator exposing static Swagger and ReDoc HTML rendering helpers."""

from __future__ import annotations

import json

from fastapi.openapi.utils import get_openapi

from src.api.main import app


def generate_openapi_json() -> str:
    """Compile the core app OpenAPI schema into JSON format."""
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )
    return json.dumps(schema, indent=2)


def render_swagger_ui_html() -> str:
    """Generate the static HTML template hosting Swagger UI client page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
    <link rel="stylesheet" type="text/css" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <title>Swagger UI - ScamShield</title>
    </head>
    <body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
      const ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      })
    </script>
    </body>
    </html>
    """


def render_redoc_ui_html() -> str:
    """Generate the static HTML template hosting ReDoc documentation client page."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
    <title>ReDoc - ScamShield</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>body { margin: 0; padding: 0; }</style>
    </head>
    <body>
    <redoc spec-url='/openapi.json'></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@next/bundles/redoc.standalone.js"></script>
    </body>
    </html>
    """
