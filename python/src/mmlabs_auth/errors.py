"""Fail-closed errors of the caches. Messages are fixed strings: no URL, body or token."""


class JwksUnavailableError(Exception):
    """No usable signing keys: the JWKS could not be fetched and the cache is empty or older
    than its maximum TTL."""

    def __init__(self) -> None:
        super().__init__("mmlabs-auth: jwks unavailable")


class CatalogUnavailableError(Exception):
    """The role catalog could not be fetched and the cache is empty or too stale."""

    def __init__(self) -> None:
        super().__init__("mmlabs-auth: role catalog unavailable")


class CatalogConfigError(Exception):
    """The role catalog answered 404: unknown or disabled app key (a configuration error)."""

    def __init__(self) -> None:
        super().__init__("mmlabs-auth: role catalog not found for this app key")
