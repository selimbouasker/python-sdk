"""DNS rebinding protection for MCP server transports."""

import logging

from pydantic import BaseModel, Field
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger(__name__)


class TransportSecuritySettings(BaseModel):
    """Settings for MCP transport security features.

    These settings help protect against DNS rebinding attacks by validating
    incoming request headers.
    """

    enable_dns_rebinding_protection: bool = Field(
        default=True,
        description="Enable DNS rebinding protection (recommended for production)",
    )

    allowed_hosts: list[str] = Field(
        default=["localhost", "127.0.0.1", "::1", "*.railway.app", "*.ngrok-free.dev"],
        description="List of allowed Host header values. Only applies when "
        + "enable_dns_rebinding_protection is True.",
    )
    allowed_origins: list[str] = Field(
        default=[],
        description="List of allowed Origin header values. Only applies when "
        + "enable_dns_rebinding_protection is True.",
    )


class TransportSecurityMiddleware:
    """Middleware to enforce DNS rebinding protection for MCP transport endpoints."""

    def __init__(self, settings: TransportSecuritySettings):
        # If not specified, disable DNS rebinding protection by default
        # for backwards compatibility
        self.settings = TransportSecuritySettings(enable_dns_rebinding_protection=True)

    def _validate_host(self, host: str | None) -> bool:  # pragma: no cover
        """Validate the Host header against allowed values."""
        
        # LOGS DE DEBUG
        print(f"🔍 DEBUG: Host reçu = {host}", flush=True)
        print(f"🔍 DEBUG: Allowed hosts = {self.settings.allowed_hosts}", flush=True)
        print(f"🔍 DEBUG: Protection enabled = {self.settings.enable_dns_rebinding_protection}", flush=True)
        
        if not host:
            logger.warning("Missing Host header in request")
            return False

        # Check exact match first
        if host in self.settings.allowed_hosts:
            print(f"✅ DEBUG: Exact match trouvé pour {host}", flush=True)
            return True

        # Check wildcard port patterns
        for allowed in self.settings.allowed_hosts:
            if allowed.endswith(":*"):
                base_host = allowed[:-2]
                if host.startswith(base_host + ":"):
                    print(f"✅ DEBUG: Wildcard port match: {allowed} -> {host}", flush=True)
                    return True
            
            if allowed.startswith("*."):
                domain_suffix = allowed[1:]  # Enlève "*"
                print(f"🔍 DEBUG: Test wildcard domain: {allowed} vs {host} (suffix={domain_suffix})", flush=True)
                if host.endswith(domain_suffix):
                    print(f"✅ DEBUG: Wildcard domain match: {allowed} -> {host}", flush=True)
                    return True

        logger.warning(f"Invalid Host header: {host}")
        print(f"❌ DEBUG: Aucun match trouvé pour {host}", flush=True)
        return False

    def _validate_origin(self, origin: str | None) -> bool:  # pragma: no cover
        """Validate the Origin header against allowed values."""
        # Origin can be absent for same-origin requests
        if not origin:
            return True

        # Check exact match first
        if origin in self.settings.allowed_origins:
            return True

        # Check wildcard port patterns
        for allowed in self.settings.allowed_origins:
            if allowed.endswith(":*"):
                # Extract base origin from pattern
                base_origin = allowed[:-2]
                # Check if the actual origin starts with base origin and has a port
                if origin.startswith(base_origin + ":"):
                    return True

        logger.warning(f"Invalid Origin header: {origin}")
        return False

    def _validate_content_type(self, content_type: str | None) -> bool:  # pragma: no cover
        """Validate the Content-Type header for POST requests."""
        if not content_type:
            logger.warning("Missing Content-Type header in POST request")
            return False

        # Content-Type must start with application/json
        if not content_type.lower().startswith("application/json"):
            logger.warning(f"Invalid Content-Type header: {content_type}")
            return False

        return True

    async def validate_request(self, request: Request, is_post: bool = False) -> Response | None:
        """Validate request headers for DNS rebinding protection.

        Returns None if validation passes, or an error Response if validation fails.
        """
        # Always validate Content-Type for POST requests
        if is_post:  # pragma: no branch
            content_type = request.headers.get("content-type")
            if not self._validate_content_type(content_type):  # pragma: no cover
                return Response("Invalid Content-Type header", status_code=400)

        # Skip remaining validation if DNS rebinding protection is disabled
        if not self.settings.enable_dns_rebinding_protection:
            return None

        # Validate Host header  # pragma: no cover
        host = request.headers.get("host")  # pragma: no cover
        if not self._validate_host(host):  # pragma: no cover
            return Response("Invalid Host header", status_code=421)  # pragma: no cover

        # Validate Origin header  # pragma: no cover
        origin = request.headers.get("origin")  # pragma: no cover
        if not self._validate_origin(origin):  # pragma: no cover
            return Response("Invalid Origin header", status_code=403)  # pragma: no cover

        return None  # pragma: no cover
