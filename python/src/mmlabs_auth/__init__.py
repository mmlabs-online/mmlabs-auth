"""mmlabs-auth: server-side verification of mmlabs Identity access tokens.

The FastAPI integration lives in `mmlabs_auth.fastapi` (extra `mmlabs-auth[fastapi]`).
"""

from mmlabs_auth.access_token import InvalidAccessTokenError, verify_access_token
from mmlabs_auth.authz import permits
from mmlabs_auth.catalog import RoleCatalogCache
from mmlabs_auth.errors import CatalogConfigError, CatalogUnavailableError, JwksUnavailableError
from mmlabs_auth.jwks import JwksCache
from mmlabs_auth.verifier import AccessTokenVerifier

__version__ = "0.1.0"

__all__ = [
    "AccessTokenVerifier",
    "CatalogConfigError",
    "CatalogUnavailableError",
    "InvalidAccessTokenError",
    "JwksCache",
    "JwksUnavailableError",
    "RoleCatalogCache",
    "__version__",
    "permits",
    "verify_access_token",
]
