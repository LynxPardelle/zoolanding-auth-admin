"""Closed deployment profile, selected only from Lambda server configuration.

SAM's prod spelling maps explicitly to the production descriptor scope. The
browser cannot redirect resources, hostnames, cookie namespaces or keys.
"""
import os
from types import MappingProxyType

_PROFILES = {
    "test": {
        "environment": "test", "samEnvironment": "test", "stage": "test",
        "adminHost": "admin-test.thehairnarrative.com",
        "adminOrigin": "https://admin-test.thehairnarrative.com",
        "serviceBindingId": "thn-journal-test-v2",
        "cookieNamespace": "endefiz7dkk635k6di6k",
        "authStack": "zoolanding-auth-admin-test",
        "hubStack": "zoolanding-content-hub-test",
        "registryPartitionKey": "SERVICE_BINDING#test#thn-journal-test-v2",
        "currentUserPartitionKey": "CURRENT_USER#test#thn-journal-test-v2",
    },
    "production": {
        "environment": "production", "samEnvironment": "prod", "stage": "prod",
        "adminHost": "admin.thehairnarrative.com",
        "adminOrigin": "https://admin.thehairnarrative.com",
        "serviceBindingId": "thn-journal-production-v2",
        "cookieNamespace": "ltnafwb6videyraictgp",
        "authStack": "zoolanding-auth-admin-prod",
        "hubStack": "zoolanding-content-hub-prod",
        "registryPartitionKey": "SERVICE_BINDING#production#thn-journal-production-v2",
        "currentUserPartitionKey": "CURRENT_USER#production#thn-journal-production-v2",
    },
}
_selection = os.environ.get("THN_DEPLOYMENT_ENVIRONMENT", "test")
if _selection not in _PROFILES:
    raise RuntimeError("THN deployment profile is unavailable")
PROFILE = MappingProxyType(_PROFILES[_selection])
