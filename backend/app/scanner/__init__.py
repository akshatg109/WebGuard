"""Safe, passive HTTP collection foundation for the WebGuard scanner.

This package intentionally contains no individual security checks or public API.
"""

from app.scanner.config import ScannerSettings
from app.scanner.service import ScannerService

__all__ = ["ScannerService", "ScannerSettings"]
