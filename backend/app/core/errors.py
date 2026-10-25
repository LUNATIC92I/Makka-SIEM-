"""Domain exceptions. Messages must never include secrets."""


class MakkadiError(Exception):
    """Base error."""


class ValidationFailed(MakkadiError):
    pass


class OutboundBlocked(MakkadiError):
    """Raised when an outbound request targets a forbidden destination (SSRF guard)."""


class ConnectorError(MakkadiError):
    def __init__(self, message: str, *, retryable: bool = False, status_code: int | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


class RateLimited(ConnectorError):
    def __init__(self, message: str = "Limite de requêtes atteinte", retry_after: float | None = None):
        super().__init__(message, retryable=True, status_code=429)
        self.retry_after = retry_after


class AuthExpired(ConnectorError):
    def __init__(self, message: str = "Jeton expiré ou invalide"):
        super().__init__(message, retryable=True, status_code=401)
