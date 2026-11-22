from typing import Any

ErrorDetails = list[dict[str, Any]]


class AppError(Exception):
    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        details: ErrorDetails | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details
        self.headers = headers


def error_body(
    code: str,
    message: str,
    details: ErrorDetails | None = None,
) -> dict[str, Any]:
    return {"error": {"code": code, "message": message, "details": details}}
