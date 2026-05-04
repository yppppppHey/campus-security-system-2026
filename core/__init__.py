# 核心模块包
"""
校园安全防护系统核心模块

包含:
    - database: 数据库管理
    - auth: 用户认证
    - rbac: 权限控制
    - encryption: 国密SM4加密
    - privacy: 差分隐私
    - masking: 数据脱敏
    - audit: 安全审计
"""

from .database import init_database, get_db, get_db_connection, DatabaseManager
from .auth import User, AuthenticationService, PasswordHasher, PasswordValidator, init_default_users
from .rbac import RBACManager, Permission, permission_required, role_required, init_default_roles_permissions
from .encryption import SM4Encryptor, SM4, KeyManager
from .privacy import DifferentialPrivacy, PrivacyQueryEngine, PrivacyBudgetTracker
from .masking import DataMasker, MaskingPolicy, DynamicMasker, MaskingStrategy
from .audit import AuditLogger, AuditEventType, RiskLevel

__all__ = [
    # 数据库
    'init_database',
    'get_db',
    'get_db_connection',
    'DatabaseManager',

    # 认证
    'User',
    'AuthenticationService',
    'PasswordHasher',
    'PasswordValidator',
    'init_default_users',

    # RBAC
    'RBACManager',
    'Permission',
    'permission_required',
    'role_required',
    'init_default_roles_permissions',

    # 加密
    'SM4Encryptor',
    'SM4',
    'KeyManager',

    # 差分隐私
    'DifferentialPrivacy',
    'PrivacyQueryEngine',
    'PrivacyBudgetTracker',

    # 脱敏
    'DataMasker',
    'MaskingPolicy',
    'DynamicMasker',
    'MaskingStrategy',

    # 审计
    'AuditLogger',
    'AuditEventType',
    'RiskLevel',
]