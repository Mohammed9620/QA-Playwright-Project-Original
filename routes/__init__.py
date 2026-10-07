"""
routes package
--------------
Exports Flask blueprints:
  - auth: authentication and user management routes
  - scan: scanning, SSE streaming, and reporting routes
"""

from .auth import auth
from .scan import scan

__all__ = ["auth", "scan"]
