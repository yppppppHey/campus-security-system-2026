# 路由模块包
"""
校园安全防护系统路由模块

包含:
    - auth: 认证路由
    - main: 主页面路由
    - admin: 管理后台路由
    - data: 数据管理路由
    - api: API接口路由
"""

from .auth import auth_bp
from .main import main_bp
from .admin import admin_bp
from .data import data_bp
from .api import api_bp

__all__ = [
    'auth_bp',
    'main_bp',
    'admin_bp',
    'data_bp',
    'api_bp'
]