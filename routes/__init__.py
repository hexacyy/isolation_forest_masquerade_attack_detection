# This file makes the routes directory a Python package
# It can be empty or contain package-level imports

from .auth import auth_bp
from .prediction import prediction_bp
from .dashboard import dashboard_bp
from .admin import admin_bp

__all__ = ['auth_bp', 'prediction_bp', 'dashboard_bp', 'admin_bp']