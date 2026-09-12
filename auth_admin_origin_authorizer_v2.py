"""Fail-closed HTTP API origin authorizer for the isolated THN TEST boundary."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
from collections.abc import Mapping
from typing import Any


_HEADER_NAME = "x-zlp-origin-verify"
_CURRENT_DIGEST_ENV = "THN_AUTH_V2_ORIGIN_HEADER_SHA256_CURRENT"
_PREVIOUS_DIGEST_ENV = "THN_AUTH_V2_ORIGIN_HEADER_SHA256_PREVIOUS"
_DISABLED_DIGEST = "0" * 64
_DIGEST_RE = re.compile(r"^[a-f0-9]{64}$")
# A 32-byte URL-safe base64 value without padding is exactly 43 characters.
_PROOF_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_ADMIN_HOST = "admin-test.thehairnarrative.com"
_ADMIN_ORIGIN = f"https://{_ADMIN_HOST}"
_ALLOWED_ROUTES = frozenset(
    {
        ("POST", "/auth-v2/session/signin"),
        ("POST", "/auth-v2/session/challenge/respond"),
        ("POST", "/auth-v2/session/mfa/setup"),
        ("POST", "/auth-v2/session/mfa/verify"),
        ("GET", "/auth-v2/session/me"),
        ("POST", "/auth-v2/session/logout"),
    }
)


def lambda_handler(event: Mapping[str, Any], context: Any) -> dict[str, Any]:
    """Authorize only an exact TEST route carrying a reviewed origin proof."""

    del context
    try:
        if not _valid_route(event):
            return _deny()
        proof = _single_header(event, _HEADER_NAME)
        viewer_ip = _viewer_ip(event)
        method = str(event["requestContext"]["http"]["method"]).upper()
        forwarded_host = _single_header(event, "x-forwarded-host")
        origin = _single_header(event, "origin")
        identity_source = event.get("identitySource")
        if (
            not _PROOF_RE.fullmatch(proof)
            or not viewer_ip
            or forwarded_host != _ADMIN_HOST
            or (method != "GET" and origin != _ADMIN_ORIGIN)
            or (origin and origin != _ADMIN_ORIGIN)
            or not isinstance(identity_source, list)
            or len(identity_source) != 1
            or identity_source[0] != proof
        ):
            return _deny()
        proof_digest = hashlib.sha256(proof.encode("utf-8")).hexdigest()
        configured = _configured_digests()
        if configured is None:
            return _deny()
        current, previous = configured
        current_matches = hmac.compare_digest(proof_digest, current)
        previous_matches = hmac.compare_digest(proof_digest, previous)
        if current_matches or (previous != _DISABLED_DIGEST and previous_matches):
            return {
                "isAuthorized": True,
                "context": {"originVerified": True, "viewerIp": viewer_ip},
            }
    except Exception:
        pass
    return _deny()


def _configured_digests() -> tuple[str, str] | None:
    current = str(os.environ.get(_CURRENT_DIGEST_ENV) or "")
    previous = str(os.environ.get(_PREVIOUS_DIGEST_ENV) or _DISABLED_DIGEST)
    if (
        not _DIGEST_RE.fullmatch(current)
        or current == _DISABLED_DIGEST
        or not _DIGEST_RE.fullmatch(previous)
    ):
        return None
    if previous != _DISABLED_DIGEST and hmac.compare_digest(current, previous):
        return None
    return current, previous


def _valid_route(event: Mapping[str, Any]) -> bool:
    if event.get("version") != "2.0" or event.get("type") != "REQUEST":
        return False
    context = event.get("requestContext")
    context = context if isinstance(context, Mapping) else {}
    http = context.get("http")
    http = http if isinstance(http, Mapping) else {}
    method = str(http.get("method") or "").upper()
    path = str(http.get("path") or "")
    route = (method, path)
    if (
        context.get("stage") != "test"
        or route not in _ALLOWED_ROUTES
        or event.get("routeKey") != f"{method} {path}"
        or context.get("routeKey") != f"{method} {path}"
        or event.get("rawPath") != path
    ):
        return False
    route_arn = str(event.get("routeArn") or "")
    arn_parts = route_arn.split(":", 5)
    if (
        len(arn_parts) != 6
        or arn_parts[0] != "arn"
        or arn_parts[2] != "execute-api"
        or context.get("accountId") != arn_parts[4]
    ):
        return False
    resource_parts = arn_parts[5].split("/", 3)
    return (
        len(resource_parts) == 4
        and bool(resource_parts[0])
        and context.get("apiId") == resource_parts[0]
        and resource_parts[1] == "test"
        and resource_parts[2] == method
        and f"/{resource_parts[3]}" == path
    )


def _viewer_ip(event: Mapping[str, Any]) -> str:
    raw = _single_header(event, "x-zlp-viewer-ip")
    if not raw or "," in raw or raw != raw.strip():
        return ""
    try:
        return ipaddress.ip_address(raw).compressed
    except ValueError:
        return ""


def _single_header(event: Mapping[str, Any], name: str) -> str:
    headers = event.get("headers")
    headers = headers if isinstance(headers, Mapping) else {}
    matches = [
        value
        for key, value in headers.items()
        if str(key).lower() == name and isinstance(value, str)
    ]
    return matches[0] if len(matches) == 1 else ""


def _deny() -> dict[str, Any]:
    return {"isAuthorized": False, "context": {}}
