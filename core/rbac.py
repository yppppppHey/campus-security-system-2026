#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
RBAC权限控制模块
实现基于角色的访问控制(RBAC)系统

功能:
    - 角色管理
    - 权限管理
    - 权限检查
    - 访问控制装饰器
"""

import functools
from typing import Optional, List, Dict, Set, Callable, Any, Tuple
from datetime import datetime
from enum import IntEnum
import logging

from flask import abort, redirect, url_for, flash, request, session, jsonify
from flask_login import current_user

logger = logging.getLogger(__name__)


class RoleLevel(IntEnum):
    """角色级别枚举"""
    ADMIN = 100      # 系统管理员
    SECURITY = 80    # 安全员
    AUDITOR = 60     # 审计员
    USER = 40        # 普通用户
    GUEST = 20       # 访客


class Permission:
    """权限常量定义"""

    # 用户管理
    USER_VIEW = 'user:view'
    USER_CREATE = 'user:create'
    USER_UPDATE = 'user:update'
    USER_DELETE = 'user:delete'
    USER_RESET_PASSWORD = 'user:reset_password'

    # 角色管理
    ROLE_VIEW = 'role:view'
    ROLE_CREATE = 'role:create'
    ROLE_UPDATE = 'role:update'
    ROLE_DELETE = 'role:delete'

    # 数据管理
    DATA_VIEW = 'data:view'
    DATA_CREATE = 'data:create'
    DATA_UPDATE = 'data:update'
    DATA_DELETE = 'data:delete'
    DATA_EXPORT = 'data:export'
    DATA_IMPORT = 'data:import'

    # 敏感数据
    SENSITIVE_VIEW = 'sensitive:view'
    SENSITIVE_DECRYPT = 'sensitive:decrypt'
    SENSITIVE_MASK = 'sensitive:mask'

    # 加密操作
    ENCRYPT_FILE = 'encrypt:file'
    DECRYPT_FILE = 'decrypt:file'

    # 差分隐私
    PRIVACY_QUERY = 'privacy:query'
    PRIVACY_CONFIG = 'privacy:config'

    # 审计日志
    AUDIT_VIEW = 'audit:view'
    AUDIT_EXPORT = 'audit:export'
    AUDIT_ANALYZE = 'audit:analyze'

    # 系统管理
    SYSTEM_CONFIG = 'system:config'
    SYSTEM_MONITOR = 'system:monitor'
    SYSTEM_BACKUP = 'system:backup'

    # 安全事件
    SECURITY_VIEW = 'security:view'
    SECURITY_HANDLE = 'security:handle'


class RBACManager:
    """
    RBAC管理器
    实现角色和权限的管理
    """

    # 默认角色定义
    DEFAULT_ROLES = [
        {
            'name': '系统管理员',
            'code': 'admin',
            'description': '拥有系统所有权限',
            'level': RoleLevel.ADMIN
        },
        {
            'name': '安全员',
            'code': 'security',
            'description': '负责数据安全和加密管理',
            'level': RoleLevel.SECURITY
        },
        {
            'name': '审计员',
            'code': 'auditor',
            'description': '负责审计日志查看和分析',
            'level': RoleLevel.AUDITOR
        },
        {
            'name': '普通用户',
            'code': 'user',
            'description': '普通数据访问权限',
            'level': RoleLevel.USER
        },
        {
            'name': '访客',
            'code': 'guest',
            'description': '只读访问权限',
            'level': RoleLevel.GUEST
        }
    ]

    # 默认权限定义
    DEFAULT_PERMISSIONS = [
        # 用户管理
        {'name': '查看用户', 'code': Permission.USER_VIEW, 'resource': 'user', 'action': 'view'},
        {'name': '创建用户', 'code': Permission.USER_CREATE, 'resource': 'user', 'action': 'create'},
        {'name': '编辑用户', 'code': Permission.USER_UPDATE, 'resource': 'user', 'action': 'update'},
        {'name': '删除用户', 'code': Permission.USER_DELETE, 'resource': 'user', 'action': 'delete'},
        {'name': '重置密码', 'code': Permission.USER_RESET_PASSWORD, 'resource': 'user', 'action': 'reset_password'},

        # 角色管理
        {'name': '查看角色', 'code': Permission.ROLE_VIEW, 'resource': 'role', 'action': 'view'},
        {'name': '创建角色', 'code': Permission.ROLE_CREATE, 'resource': 'role', 'action': 'create'},
        {'name': '编辑角色', 'code': Permission.ROLE_UPDATE, 'resource': 'role', 'action': 'update'},
        {'name': '删除角色', 'code': Permission.ROLE_DELETE, 'resource': 'role', 'action': 'delete'},

        # 数据管理
        {'name': '查看数据', 'code': Permission.DATA_VIEW, 'resource': 'data', 'action': 'view'},
        {'name': '创建数据', 'code': Permission.DATA_CREATE, 'resource': 'data', 'action': 'create'},
        {'name': '编辑数据', 'code': Permission.DATA_UPDATE, 'resource': 'data', 'action': 'update'},
        {'name': '删除数据', 'code': Permission.DATA_DELETE, 'resource': 'data', 'action': 'delete'},
        {'name': '导出数据', 'code': Permission.DATA_EXPORT, 'resource': 'data', 'action': 'export'},
        {'name': '导入数据', 'code': Permission.DATA_IMPORT, 'resource': 'data', 'action': 'import'},

        # 敏感数据
        {'name': '查看敏感数据', 'code': Permission.SENSITIVE_VIEW, 'resource': 'sensitive', 'action': 'view'},
        {'name': '解密敏感数据', 'code': Permission.SENSITIVE_DECRYPT, 'resource': 'sensitive', 'action': 'decrypt'},
        {'name': '脱敏敏感数据', 'code': Permission.SENSITIVE_MASK, 'resource': 'sensitive', 'action': 'mask'},

        # 加密操作
        {'name': '文件加密', 'code': Permission.ENCRYPT_FILE, 'resource': 'encrypt', 'action': 'file'},
        {'name': '文件解密', 'code': Permission.DECRYPT_FILE, 'resource': 'decrypt', 'action': 'file'},

        # 差分隐私
        {'name': '隐私查询', 'code': Permission.PRIVACY_QUERY, 'resource': 'privacy', 'action': 'query'},
        {'name': '隐私配置', 'code': Permission.PRIVACY_CONFIG, 'resource': 'privacy', 'action': 'config'},

        # 审计日志
        {'name': '查看审计日志', 'code': Permission.AUDIT_VIEW, 'resource': 'audit', 'action': 'view'},
        {'name': '导出审计日志', 'code': Permission.AUDIT_EXPORT, 'resource': 'audit', 'action': 'export'},
        {'name': '分析审计日志', 'code': Permission.AUDIT_ANALYZE, 'resource': 'audit', 'action': 'analyze'},

        # 系统管理
        {'name': '系统配置', 'code': Permission.SYSTEM_CONFIG, 'resource': 'system', 'action': 'config'},
        {'name': '系统监控', 'code': Permission.SYSTEM_MONITOR, 'resource': 'system', 'action': 'monitor'},
        {'name': '系统备份', 'code': Permission.SYSTEM_BACKUP, 'resource': 'system', 'action': 'backup'},

        # 安全事件
        {'name': '查看安全事件', 'code': Permission.SECURITY_VIEW, 'resource': 'security', 'action': 'view'},
        {'name': '处理安全事件', 'code': Permission.SECURITY_HANDLE, 'resource': 'security', 'action': 'handle'},
    ]

    # 角色权限映射
    ROLE_PERMISSIONS = {
        'admin': '*',  # 管理员拥有所有权限
        'security': [
            Permission.USER_VIEW,
            Permission.DATA_VIEW, Permission.DATA_CREATE, Permission.DATA_UPDATE,
            Permission.SENSITIVE_VIEW, Permission.SENSITIVE_DECRYPT, Permission.SENSITIVE_MASK,
            Permission.ENCRYPT_FILE, Permission.DECRYPT_FILE,
            Permission.PRIVACY_QUERY,
            Permission.AUDIT_VIEW,
            Permission.SECURITY_VIEW, Permission.SECURITY_HANDLE
        ],
        'auditor': [
            Permission.USER_VIEW,
            Permission.DATA_VIEW,
            Permission.SENSITIVE_VIEW, Permission.SENSITIVE_MASK,
            Permission.AUDIT_VIEW, Permission.AUDIT_EXPORT, Permission.AUDIT_ANALYZE,
            Permission.SECURITY_VIEW
        ],
        'user': [
            Permission.DATA_VIEW,
            Permission.SENSITIVE_VIEW,
            Permission.ENCRYPT_FILE, Permission.DECRYPT_FILE,
            Permission.PRIVACY_QUERY
        ],
        'guest': [
            Permission.DATA_VIEW,
            Permission.SENSITIVE_VIEW
        ]
    }

    def __init__(self):
        """初始化RBAC管理器"""
        self._permission_cache: Dict[int, Set[str]] = {}

    def init_default_data(self):
        """初始化默认角色和权限数据"""
        from core.database import get_db
        db = get_db()

        # 检查是否已初始化
        role_count = db.fetch_count('roles')
        if role_count > 0:
            logger.info("角色权限数据已存在，跳过初始化")
            return

        # 创建权限
        for perm in self.DEFAULT_PERMISSIONS:
            db.execute(
                """
                INSERT INTO permissions (name, code, resource, action, description)
                VALUES (?, ?, ?, ?, ?)
                """,
                (perm['name'], perm['code'], perm['resource'], perm['action'], perm.get('description', ''))
            )

        # 创建角色
        for role in self.DEFAULT_ROLES:
            db.execute(
                """
                INSERT INTO roles (name, code, description, level)
                VALUES (?, ?, ?, ?)
                """,
                (role['name'], role['code'], role['description'], role['level'])
            )

        # 分配角色权限
        self._assign_role_permissions()

        logger.info("角色权限数据初始化完成")

    def _assign_role_permissions(self):
        """分配角色权限"""
        from core.database import get_db
        db = get_db()

        for role_code, permissions in self.ROLE_PERMISSIONS.items():
            # 获取角色ID
            role = db.fetch_one("SELECT id FROM roles WHERE code = ?", (role_code,))
            if not role:
                continue

            role_id = role['id']

            if permissions == '*':
                # 所有权限
                perm_records = db.fetch_all("SELECT id FROM permissions")
                for perm in perm_records:
                    try:
                        db.execute(
                            "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                            (role_id, perm['id'])
                        )
                    except Exception:
                        pass  # 忽略重复
            else:
                # 指定权限
                for perm_code in permissions:
                    perm = db.fetch_one("SELECT id FROM permissions WHERE code = ?", (perm_code,))
                    if perm:
                        try:
                            db.execute(
                                "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                                (role_id, perm['id'])
                            )
                        except Exception:
                            pass

    def get_role(self, role_id: int) -> Optional[Dict]:
        """
        获取角色信息

        Args:
            role_id: 角色ID

        Returns:
            Dict: 角色信息
        """
        from core.database import get_db
        db = get_db()
        return db.fetch_one("SELECT * FROM roles WHERE id = ?", (role_id,))

    def get_all_roles(self) -> List[Dict]:
        """
        获取所有角色

        Returns:
            List[Dict]: 角色列表
        """
        from core.database import get_db
        db = get_db()
        return db.fetch_all("SELECT * FROM roles ORDER BY level DESC")

    def get_role_permissions(self, role_id: int) -> List[str]:
        """
        获取角色的权限列表

        Args:
            role_id: 角色ID

        Returns:
            List[str]: 权限代码列表
        """
        from core.database import get_db
        db = get_db()

        results = db.fetch_all(
            """
            SELECT p.code
            FROM permissions p
            JOIN role_permissions rp ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            ORDER BY p.resource, p.action
            """,
            (role_id,)
        )
        return [r['code'] for r in results]

    def check_permission(self, user_id: int, permission: str) -> bool:
        """
        检查用户是否拥有指定权限

        Args:
            user_id: 用户ID
            permission: 权限代码

        Returns:
            bool: 是否拥有权限
        """
        from core.database import get_db
        from core.auth import User

        # 检查缓存
        if user_id in self._permission_cache:
            return permission in self._permission_cache[user_id]

        # 获取用户
        user = User.get(user_id)
        if not user:
            return False

        # 获取用户权限
        permissions = set(user.get_permissions())
        self._permission_cache[user_id] = permissions

        return permission in permissions

    def check_any_permission(self, user_id: int, permissions: List[str]) -> bool:
        """
        检查用户是否拥有任一权限

        Args:
            user_id: 用户ID
            permissions: 权限代码列表

        Returns:
            bool: 是否拥有任一权限
        """
        for perm in permissions:
            if self.check_permission(user_id, perm):
                return True
        return False

    def check_all_permissions(self, user_id: int, permissions: List[str]) -> bool:
        """
        检查用户是否拥有所有权限

        Args:
            user_id: 用户ID
            permissions: 权限代码列表

        Returns:
            bool: 是否拥有所有权限
        """
        for perm in permissions:
            if not self.check_permission(user_id, perm):
                return False
        return True

    def clear_cache(self, user_id: int = None):
        """
        清除权限缓存

        Args:
            user_id: 用户ID，为None时清除所有缓存
        """
        if user_id:
            self._permission_cache.pop(user_id, None)
        else:
            self._permission_cache.clear()

    def create_role(self, name: str, code: str, description: str = '',
                    level: int = RoleLevel.USER) -> Tuple[bool, str, Optional[int]]:
        """
        创建角色

        Args:
            name: 角色名称
            code: 角色代码
            description: 描述
            level: 级别

        Returns:
            Tuple[bool, str, Optional[int]]: (是否成功, 消息, 角色ID)
        """
        from core.database import get_db
        db = get_db()

        try:
            cursor = db.execute(
                """
                INSERT INTO roles (name, code, description, level)
                VALUES (?, ?, ?, ?)
                """,
                (name, code, description, level)
            )
            role_id = cursor.lastrowid
            logger.info(f"创建角色: {name}")
            return True, "角色创建成功", role_id
        except Exception as e:
            logger.error(f"创建角色失败: {e}")
            return False, f"创建失败: {str(e)}", None

    def update_role(self, role_id: int, name: str = None, description: str = None,
                    level: int = None) -> Tuple[bool, str]:
        """
        更新角色

        Args:
            role_id: 角色ID
            name: 名称
            description: 描述
            level: 级别

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        from core.database import get_db
        db = get_db()

        updates = []
        params = []
        if name:
            updates.append("name = ?")
            params.append(name)
        if description is not None:
            updates.append("description = ?")
            params.append(description)
        if level is not None:
            updates.append("level = ?")
            params.append(level)

        if not updates:
            return False, "没有要更新的内容"

        params.extend([datetime.now(), role_id])
        query = f"UPDATE roles SET {', '.join(updates)}, updated_at = ? WHERE id = ?"

        try:
            db.execute(query, tuple(params))
            logger.info(f"更新角色: ID={role_id}")
            return True, "角色更新成功"
        except Exception as e:
            logger.error(f"更新角色失败: {e}")
            return False, f"更新失败: {str(e)}"

    def delete_role(self, role_id: int) -> Tuple[bool, str]:
        """
        删除角色

        Args:
            role_id: 角色ID

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        from core.database import get_db
        db = get_db()

        # 检查是否有用户使用此角色
        count = db.fetch_count('users', 'role_id = ?', (role_id,))
        if count > 0:
            return False, f"无法删除，有{count}个用户正在使用此角色"

        try:
            db.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))
            db.execute("DELETE FROM roles WHERE id = ?", (role_id,))
            logger.info(f"删除角色: ID={role_id}")
            return True, "角色删除成功"
        except Exception as e:
            logger.error(f"删除角色失败: {e}")
            return False, f"删除失败: {str(e)}"

    def assign_permissions(self, role_id: int, permission_ids: List[int]) -> Tuple[bool, str]:
        """
        分配权限给角色

        Args:
            role_id: 角色ID
            permission_ids: 权限ID列表

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        from core.database import get_db
        db = get_db()

        try:
            # 先删除原有权限
            db.execute("DELETE FROM role_permissions WHERE role_id = ?", (role_id,))

            # 添加新权限
            for perm_id in permission_ids:
                db.execute(
                    "INSERT INTO role_permissions (role_id, permission_id) VALUES (?, ?)",
                    (role_id, perm_id)
                )

            logger.info(f"分配权限给角色: role_id={role_id}, permissions={permission_ids}")
            return True, "权限分配成功"
        except Exception as e:
            logger.error(f"分配权限失败: {e}")
            return False, f"分配失败: {str(e)}"

    def get_all_permissions(self) -> List[Dict]:
        """
        获取所有权限

        Returns:
            List[Dict]: 权限列表
        """
        from core.database import get_db
        db = get_db()
        return db.fetch_all("SELECT * FROM permissions ORDER BY resource, action")

    def get_permissions_by_resource(self, resource: str) -> List[Dict]:
        """
        获取指定资源的权限

        Args:
            resource: 资源名称

        Returns:
            List[Dict]: 权限列表
        """
        from core.database import get_db
        db = get_db()
        return db.fetch_all(
            "SELECT * FROM permissions WHERE resource = ? ORDER BY action",
            (resource,)
        )


def permission_required(*permissions: str):
    """
    权限检查装饰器

    Args:
        permissions: 需要的权限代码

    Usage:
        @permission_required('user:view', 'user:create')
        def some_view():
            pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('请先登录', 'warning')
                return redirect(url_for('auth.login', next=request.url))

            # 检查权限
            rbac = RBACManager()
            has_permission = any(
                rbac.check_permission(current_user.id, perm)
                for perm in permissions
            )

            if not has_permission:
                # 记录权限拒绝事件
                from core.audit import AuditLogger
                audit = AuditLogger()
                audit.log_action(
                    user_id=current_user.id,
                    username=current_user.username,
                    action='permission_denied',
                    resource=request.endpoint,
                    ip_address=request.remote_addr,
                    details=f"需要权限: {', '.join(permissions)}"
                )

                flash('您没有权限执行此操作', 'danger')
                abort(403)

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def api_permission_required(*permissions: str):
    """
    API权限检查装饰器（返回JSON错误响应）

    Args:
        permissions: 需要的权限代码
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({
                    'success': False,
                    'error': '请先登录'
                }), 401

            # 检查权限
            rbac = RBACManager()
            has_permission = any(
                rbac.check_permission(current_user.id, perm)
                for perm in permissions
            )

            if not has_permission:
                # 记录权限拒绝事件
                from core.audit import AuditLogger
                audit = AuditLogger()
                audit.log_action(
                    user_id=current_user.id,
                    username=current_user.username,
                    action='permission_denied',
                    resource=request.endpoint,
                    ip_address=request.remote_addr,
                    details=f"需要权限: {', '.join(permissions)}"
                )

                return jsonify({
                    'success': False,
                    'error': '您没有权限执行此操作'
                }), 403

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def role_required(*role_codes: str):
    """
    角色检查装饰器

    Args:
        role_codes: 需要的角色代码

    Usage:
        @role_required('admin', 'security')
        def admin_view():
            pass
    """
    def decorator(f: Callable) -> Callable:
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('请先登录', 'warning')
                return redirect(url_for('auth.login', next=request.url))

            # 获取用户角色
            role = current_user.get_role()
            if not role or role['code'] not in role_codes:
                flash('您没有权限访问此页面', 'danger')
                abort(403)

            return f(*args, **kwargs)

        return decorated_function
    return decorator


def admin_required(f: Callable) -> Callable:
    """
    管理员权限装饰器
    """
    return role_required('admin')(f)


def login_required(f: Callable) -> Callable:
    """
    登录检查装饰器（增强版）
    记录访问日志
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('请先登录', 'warning')
            return redirect(url_for('auth.login', next=request.url))

        # 记录访问
        from core.audit import AuditLogger
        audit = AuditLogger()
        audit.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='access',
            resource=request.endpoint,
            ip_address=request.remote_addr,
            details=f"访问页面: {request.path}"
        )

        return f(*args, **kwargs)

    return decorated_function


def init_default_roles_permissions():
    """初始化默认角色和权限"""
    rbac = RBACManager()
    rbac.init_default_data()


# 导入Tuple类型
from typing import Tuple


if __name__ == '__main__':
    # 测试RBAC
    rbac = RBACManager()
    print("默认角色:", [r['name'] for r in rbac.DEFAULT_ROLES])
    print("权限数量:", len(rbac.DEFAULT_PERMISSIONS))
    print("管理员权限:", rbac.ROLE_PERMISSIONS['admin'])
