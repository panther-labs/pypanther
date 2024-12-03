from typing import Any, Dict, Optional


def is_retryable_error(err: Optional[Dict[str, Any]]) -> bool:
    if err:
        if is_retryable_error_str(err.get("message", "")) or is_retryable_error_str(err.get("body", "")):
            return True
    return False


def is_retryable_error_str(err: str) -> bool:
    if not err:
        return False
    return "another upload" in err
