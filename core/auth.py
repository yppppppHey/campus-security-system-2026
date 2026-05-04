#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
认证模块
实现用户认证、密码安全、会话管理等功能

功能:
    - 用户登录/登出
    - 密码加密与验证
    - 登录尝试限制
    - 会话管理
    - 密码强度验证
"""

import os
import hashlib
import secrets
import base64
import hmac
import time
from datetime import datetime, timedelta
from typing import Optional, Tuple, List, Dict, Any
from dataclasses import dataclass
import logging
import re

from flask_login import UserMixin
from flask import current_app, session

logger = logging.getLogger(__name__)


@dataclass
class PasswordPolicy:
    """密码策略配置"""
    min_length: int = 8
    max_length: int = 128
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digit: bool = True
    require_special: bool = True
    special_chars: str = '!@#$%^&*()_+-=[]{}|;:,.<>?'
    max_age_days: int = 90
    history_count: int = 5


class PasswordHasher:
    """
    密码哈希器
    使用PBKDF2-HMAC-SHA256进行密码哈希
    """

    ITERATIONS = 100000  # 迭代次数
    SALT_LENGTH = 32      # 盐值长度
    HASH_LENGTH = 64      # 哈希值长度
    ALGORITHM = 'sha256'  # 哈希算法

    @classmethod
    def generate_salt(cls) -> str:
        """
        生成随机盐值

        Returns:
            str: 十六进制格式的盐值
        """
        return secrets.token_hex(cls.SALT_LENGTH)

    @classmethod
    def hash_password(cls, password: str, salt: str) -> str:
        """
        对密码进行哈希

        Args:
            password: 明文密码
            salt: 盐值

        Returns:
            str: 哈希后的密码
        """
        if not password or not salt:
            raise ValueError("密码和盐值不能为空")

        # 使用PBKDF2进行密钥派生
        dk = hashlib.pbkdf2_hmac(
            cls.ALGORITHM,
            password.encode('utf-8'),
            salt.encode('utf-8'),
            cls.ITERATIONS,
            dklen=cls.HASH_LENGTH
        )
        return dk.hex()

    @classmethod
    def verify_password(cls, password: str, salt: str, password_hash: str) -> bool:
        """
        验证密码

        Args:
            password: 待验证的明文密码
            salt: 盐值
            password_hash: 存储的密码哈希

        Returns:
            bool: 验证结果
        """
        if not password or not salt or not password_hash:
            return False

        computed_hash = cls.hash_password(password, salt)
        # 使用常量时间比较防止时序攻击
        return hmac.compare_digest(computed_hash, password_hash)

    @classmethod
    def needs_rehash(cls, password_hash: str) -> bool:
        """
        检查密码是否需要重新哈希
        （用于算法升级场景）

        Args:
            password_hash: 存储的密码哈希

        Returns:
            bool: 是否需要重新哈希
        """
        # 检查哈希长度是否符合当前配置
        return len(password_hash) != cls.HASH_LENGTH * 2


class PasswordValidator:
    """密码验证器"""

    def __init__(self, policy: PasswordPolicy = None):
        """
        初始化密码验证器

        Args:
            policy: 密码策略配置
        """
        self.policy = policy or PasswordPolicy()

    def validate(self, password: str) -> Tuple[bool, List[str]]:
        """
        验证密码强度

        Args:
            password: 待验证的密码

        Returns:
            Tuple[bool, List[str]]: (是否通过验证, 错误消息列表)
        """
        errors = []

        # 检查长度
        if len(password) < self.policy.min_length:
            errors.append(f"密码长度至少需要{self.policy.min_length}个字符")
        if len(password) > self.policy.max_length:
            errors.append(f"密码长度不能超过{self.policy.max_length}个字符")

        # 检查字符类型
        if self.policy.require_uppercase and not re.search(r'[A-Z]', password):
            errors.append("密码需要包含至少一个大写字母")

        if self.policy.require_lowercase and not re.search(r'[a-z]', password):
            errors.append("密码需要包含至少一个小写字母")

        if self.policy.require_digit and not re.search(r'\d', password):
            errors.append("密码需要包含至少一个数字")

        if self.policy.require_special:
            special_pattern = f'[{re.escape(self.policy.special_chars)}]'
            if not re.search(special_pattern, password):
                errors.append(f"密码需要包含至少一个特殊字符: {self.policy.special_chars}")

        # 检查常见弱密码
        weak_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'password123', 'admin', 'root', 'letmein', 'welcome'
        ]
        if password.lower() in weak_passwords:
            errors.append("密码过于简单，请使用更强的密码")

        return len(errors) == 0, errors

    def get_strength(self, password: str) -> Tuple[int, str]:
        """
        计算密码强度

        Args:
            password: 密码

        Returns:
            Tuple[int, str]: (强度分数0-100, 强度等级描述)
        """
        score = 0

        # 长度评分
        if len(password) >= 8:
            score += 20
        if len(password) >= 12:
            score += 10
        if len(password) >= 16:
            score += 10

        # 字符类型评分
        if re.search(r'[a-z]', password):
            score += 10
        if re.search(r'[A-Z]', password):
            score += 10
        if re.search(r'\d', password):
            score += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            score += 20

        # 复杂度评分
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.6:
            score += 10

        # 确定等级
        if score < 30:
            level = "弱"
        elif score < 50:
            level = "一般"
        elif score < 70:
            level = "中等"
        elif score < 90:
            level = "强"
        else:
            level = "非常强"

        return score, level


class User(UserMixin):
    """
    用户类
    实现Flask-Login要求的用户接口
    """

    def __init__(self, user_data: Dict[str, Any]):
        """
        初始化用户对象

        Args:
            user_data: 用户数据字典
        """
        self.id = user_data.get('id')
        self.username = user_data.get('username')
        self.password_hash = user_data.get('password_hash')
        self.salt = user_data.get('salt')
        self.real_name = user_data.get('real_name')
        self.email = user_data.get('email')
        self.phone = user_data.get('phone')
        self.role_id = user_data.get('role_id')
        self.department = user_data.get('department')
        self.position = user_data.get('position')
        self.status = user_data.get('status', 1)
        self.login_attempts = user_data.get('login_attempts', 0)
        self.last_login = user_data.get('last_login')
        self.last_login_ip = user_data.get('last_login_ip')
        self.password_changed_at = user_data.get('password_changed_at')
        self.created_at = user_data.get('created_at')
        self.updated_at = user_data.get('updated_at')
        self.created_by = user_data.get('created_by')

        # 角色信息（延迟加载）
        self._role = None
        self._permissions = None

    @property
    def is_active(self) -> bool:
        """用户是否激活"""
        return self.status == 1

    @property
    def is_authenticated(self) -> bool:
        """用户是否已认证"""
        return True

    @property
    def is_anonymous(self) -> bool:
        """是否匿名用户"""
        return False

    def get_id(self) -> str:
        """获取用户ID（Flask-Login要求）"""
        return str(self.id)

    def verify_password(self, password: str) -> bool:
        """
        验证密码

        Args:
            password: 明文密码

        Returns:
            bool: 验证结果
        """
        return PasswordHasher.verify_password(password, self.salt, self.password_hash)

    def get_role(self) -> Dict[str, Any]:
        """
        获取用户角色信息

        Returns:
            Dict: 角色信息
        """
        if self._role is None:
            from core.database import get_db
            db = get_db()
            self._role = db.fetch_one(
                "SELECT * FROM roles WHERE id = ?",
                (self.role_id,)
            )
        return self._role

    def get_permissions(self) -> List[str]:
        """
        获取用户权限列表

        Returns:
            List[str]: 权限代码列表
        """
        if self._permissions is None:
            from core.database import get_db
            db = get_db()
            results = db.fetch_all(
                """
                SELECT p.code
                FROM permissions p
                JOIN role_permissions rp ON p.id = rp.permission_id
                WHERE rp.role_id = ?
                """,
                (self.role_id,)
            )
            self._permissions = [r['code'] for r in results]
        return self._permissions

    def has_permission(self, permission: str) -> bool:
        """
        检查用户是否拥有指定权限

        Args:
            permission: 权限代码

        Returns:
            bool: 是否拥有权限
        """
        return permission in self.get_permissions()

    def is_admin(self) -> bool:
        """是否为管理员"""
        role = self.get_role()
        return role and role.get('code') == 'admin'

    def is_security_officer(self) -> bool:
        """是否为安全员"""
        role = self.get_role()
        return role and role.get('code') == 'security'

    def is_auditor(self) -> bool:
        """是否为审计员"""
        role = self.get_role()
        return role and role.get('code') == 'auditor'

    @staticmethod
    def get(user_id: int) -> Optional['User']:
        """
        根据ID获取用户

        Args:
            user_id: 用户ID

        Returns:
            User: 用户对象，不存在返回None
        """
        from core.database import get_db
        db = get_db()
        user_data = db.fetch_one(
            "SELECT * FROM users WHERE id = ?",
            (user_id,)
        )
        return User(user_data) if user_data else None

    @staticmethod
    def get_by_username(username: str) -> Optional['User']:
        """
        根据用户名获取用户

        Args:
            username: 用户名

        Returns:
            User: 用户对象，不存在返回None
        """
        from core.database import get_db
        db = get_db()
        user_data = db.fetch_one(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )
        return User(user_data) if user_data else None

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """
        转换为字典

        Args:
            include_sensitive: 是否包含敏感信息

        Returns:
            Dict: 用户信息字典
        """
        data = {
            'id': self.id,
            'username': self.username,
            'real_name': self.real_name,
            'email': self.email,
            'phone': self.phone,
            'role_id': self.role_id,
            'department': self.department,
            'position': self.position,
            'status': self.status,
            'last_login': str(self.last_login) if self.last_login else None,
            'created_at': str(self.created_at) if self.created_at else None,
        }
        if include_sensitive:
            data['login_attempts'] = self.login_attempts
            data['last_login_ip'] = self.last_login_ip
        return data


class AuthenticationService:
    """
    认证服务类
    提供完整的认证功能
    """

    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=30)

    def __init__(self):
        """初始化认证服务"""
        self.password_validator = PasswordValidator()

    def login(self, username: str, password: str, ip_address: str = None,
              user_agent: str = None) -> Tuple[bool, Optional[User], str]:
        """
        用户登录

        Args:
            username: 用户名
            password: 密码
            ip_address: IP地址
            user_agent: 用户代理

        Returns:
            Tuple[bool, Optional[User], str]: (是否成功, 用户对象, 消息)
        """
        from core.database import get_db
        from core.audit import AuditLogger

        db = get_db()
        audit = AuditLogger()

        # 查询用户
        user = User.get_by_username(username)
        if not user:
            audit.log_login_attempt(
                username=username,
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason="用户不存在"
            )
            return False, None, "用户名或密码错误"

        # 检查账户状态
        if user.status != 1:
            audit.log_login_attempt(
                user_id=user.id,
                username=username,
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason="账户已禁用"
            )
            return False, None, "账户已被禁用，请联系管理员"

        # 检查登录尝试次数
        if user.login_attempts >= self.MAX_LOGIN_ATTEMPTS:
            # 检查锁定是否过期
            if user.last_login:
                last_attempt = datetime.fromisoformat(str(user.last_login))
                if datetime.now() - last_attempt < self.LOCKOUT_DURATION:
                    remaining = self.LOCKOUT_DURATION - (datetime.now() - last_attempt)
                    minutes = int(remaining.total_seconds() / 60)
                    audit.log_login_attempt(
                        user_id=user.id,
                        username=username,
                        success=False,
                        ip_address=ip_address,
                        user_agent=user_agent,
                        failure_reason="账户锁定中"
                    )
                    return False, None, f"账户已锁定，请{minutes}分钟后再试"

        # 验证密码
        if not user.verify_password(password):
            # 更新登录尝试次数
            new_attempts = user.login_attempts + 1
            db.execute(
                "UPDATE users SET login_attempts = ?, last_login = ? WHERE id = ?",
                (new_attempts, datetime.now(), user.id)
            )

            audit.log_login_attempt(
                user_id=user.id,
                username=username,
                success=False,
                ip_address=ip_address,
                user_agent=user_agent,
                failure_reason=f"密码错误({new_attempts}/{self.MAX_LOGIN_ATTEMPTS})"
            )

            if new_attempts >= self.MAX_LOGIN_ATTEMPTS:
                return False, None, "密码错误次数过多，账户已锁定30分钟"
            return False, None, f"用户名或密码错误，还剩{self.MAX_LOGIN_ATTEMPTS - new_attempts}次机会"

        # 登录成功
        db.execute(
            """
            UPDATE users SET
                login_attempts = 0,
                last_login = ?,
                last_login_ip = ?
            WHERE id = ?
            """,
            (datetime.now(), ip_address, user.id)
        )

        # 记录登录日志
        audit.log_login_attempt(
            user_id=user.id,
            username=username,
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )

        logger.info(f"用户登录成功: {username} from {ip_address}")

        return True, user, "登录成功"

    def logout(self, user_id: int, username: str, ip_address: str = None):
        """
        用户登出

        Args:
            user_id: 用户ID
            username: 用户名
            ip_address: IP地址
        """
        from core.audit import AuditLogger
        audit = AuditLogger()
        audit.log_action(
            user_id=user_id,
            username=username,
            action='logout',
            resource='auth',
            ip_address=ip_address,
            details="用户登出"
        )
        logger.info(f"用户登出: {username}")

    def change_password(self, user_id: int, old_password: str,
                        new_password: str) -> Tuple[bool, str]:
        """
        修改密码

        Args:
            user_id: 用户ID
            old_password: 旧密码
            new_password: 新密码

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        from core.database import get_db

        db = get_db()

        # 获取用户
        user = User.get(user_id)
        if not user:
            return False, "用户不存在"

        # 验证旧密码
        if not user.verify_password(old_password):
            return False, "原密码错误"

        # 验证新密码强度
        valid, errors = self.password_validator.validate(new_password)
        if not valid:
            return False, "; ".join(errors)

        # 检查密码历史（不能与最近5次相同）
        # 这里简化处理，实际应存储密码历史
        if user.verify_password(new_password):
            return False, "新密码不能与当前密码相同"

        # 生成新密码哈希
        new_salt = PasswordHasher.generate_salt()
        new_hash = PasswordHasher.hash_password(new_password, new_salt)

        # 更新密码
        db.execute(
            """
            UPDATE users SET
                password_hash = ?,
                salt = ?,
                password_changed_at = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (new_hash, new_salt, datetime.now(), datetime.now(), user_id)
        )

        logger.info(f"用户修改密码: {user.username}")

        return True, "密码修改成功"

    def reset_password(self, user_id: int, new_password: str,
                       operator_id: int = None) -> Tuple[bool, str]:
        """
        重置密码（管理员操作）

        Args:
            user_id: 用户ID
            new_password: 新密码
            operator_id: 操作者ID

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        from core.database import get_db

        db = get_db()

        # 验证新密码强度
        valid, errors = self.password_validator.validate(new_password)
        if not valid:
            return False, "; ".join(errors)

        # 生成新密码哈希
        new_salt = PasswordHasher.generate_salt()
        new_hash = PasswordHasher.hash_password(new_password, new_salt)

        # 更新密码
        db.execute(
            """
            UPDATE users SET
                password_hash = ?,
                salt = ?,
                password_changed_at = ?,
                updated_at = ?,
                login_attempts = 0
            WHERE id = ?
            """,
            (new_hash, new_salt, datetime.now(), datetime.now(), user_id)
        )

        logger.info(f"密码被重置: 用户ID={user_id}, 操作者ID={operator_id}")

        return True, "密码重置成功"


def init_default_users():
    """初始化默认用户"""
    from core.database import get_db
    from core.rbac import RBACManager

    db = get_db()

    # 检查是否已有用户
    count = db.fetch_count('users')
    if count > 0:
        logger.info("默认用户已存在，跳过初始化")
        return

    # 创建默认用户
    default_users = [
        {
            'username': 'admin',
            'password': 'Admin@123',
            'real_name': '系统管理员',
            'email': 'admin@campus.edu.cn',
            'phone': '13800138000',
            'role_id': 1,  # 管理员角色
            'department': '信息中心',
            'position': '系统管理员'
        },
        {
            'username': 'security',
            'password': 'Security@123',
            'real_name': '安全员',
            'email': 'security@campus.edu.cn',
            'phone': '13800138001',
            'role_id': 2,  # 安全员角色
            'department': '安全部门',
            'position': '安全专员'
        },
        {
            'username': 'auditor',
            'password': 'Auditor@123',
            'real_name': '审计员',
            'email': 'auditor@campus.edu.cn',
            'phone': '13800138002',
            'role_id': 3,  # 审计员角色
            'department': '审计部门',
            'position': '审计专员'
        },
        {
            'username': 'user',
            'password': 'User@123',
            'real_name': '普通用户',
            'email': 'user@campus.edu.cn',
            'phone': '13800138003',
            'role_id': 4,  # 普通用户角色
            'department': '教务处',
            'position': '教务员'
        }
    ]

    for user_data in default_users:
        salt = PasswordHasher.generate_salt()
        password_hash = PasswordHasher.hash_password(user_data['password'], salt)

        db.execute(
            """
            INSERT INTO users
            (username, password_hash, salt, real_name, email, phone, role_id, department, position, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                user_data['username'],
                password_hash,
                salt,
                user_data['real_name'],
                user_data['email'],
                user_data['phone'],
                user_data['role_id'],
                user_data['department'],
                user_data['position']
            )
        )

    logger.info(f"初始化默认用户完成，共{len(default_users)}个用户")


def load_user(user_id: int) -> Optional[User]:
    """
    加载用户（Flask-Login回调）

    Args:
        user_id: 用户ID

    Returns:
        User: 用户对象
    """
    return User.get(int(user_id))


if __name__ == '__main__':
    # 测试密码哈希
    hasher = PasswordHasher()
    salt = hasher.generate_salt()
    password = "Test@123"
    hash_value = hasher.hash_password(password, salt)
    print(f"Salt: {salt}")
    print(f"Hash: {hash_value}")
    print(f"Verify: {hasher.verify_password(password, salt, hash_value)}")

    # 测试密码验证
    validator = PasswordValidator()
    valid, errors = validator.validate("Test@123")
    print(f"Valid: {valid}, Errors: {errors}")

    score, level = validator.get_strength("Test@123456!")
    print(f"Strength: {score}, Level: {level}")