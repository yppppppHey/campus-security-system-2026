#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据库模块
实现SQLite数据库的初始化、连接管理和基础操作

功能:
    - 数据库初始化和表结构创建
    - 连接池管理
    - 事务支持
    - 基础CRUD操作封装
"""

import os
import sqlite3
import threading
import uuid
from datetime import datetime
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Tuple
import logging

logger = logging.getLogger(__name__)

# 线程本地存储
_local = threading.local()


class DatabaseManager:
    """
    数据库管理器
    实现线程安全的数据库连接管理
    """

    def __init__(self, db_path: str):
        """
        初始化数据库管理器

        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_db_directory()

    def _ensure_db_directory(self):
        """确保数据库目录存在"""
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"创建数据库目录: {db_dir}")

    def get_connection(self) -> sqlite3.Connection:
        """
        获取当前线程的数据库连接

        Returns:
            sqlite3.Connection: 数据库连接对象
        """
        if not hasattr(_local, 'connection') or _local.connection is None:
            _local.connection = sqlite3.connect(
                self.db_path,
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                check_same_thread=False
            )
            _local.connection.row_factory = sqlite3.Row
            # 启用外键约束
            _local.connection.execute("PRAGMA foreign_keys = ON")
            # 设置WAL模式提高并发性能
            _local.connection.execute("PRAGMA journal_mode = WAL")
            logger.debug(f"创建新的数据库连接: {threading.current_thread().name}")
        return _local.connection

    def close_connection(self):
        """关闭当前线程的数据库连接"""
        if hasattr(_local, 'connection') and _local.connection is not None:
            _local.connection.close()
            _local.connection = None
            logger.debug(f"关闭数据库连接: {threading.current_thread().name}")

    @contextmanager
    def transaction(self):
        """
        事务上下文管理器

        Yields:
            sqlite3.Connection: 数据库连接对象
        """
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"事务回滚: {e}")
            raise

    def execute(self, query: str, params: tuple = None) -> sqlite3.Cursor:
        """
        执行SQL语句

        Args:
            query: SQL语句
            params: 参数元组

        Returns:
            sqlite3.Cursor: 游标对象
        """
        conn = self.get_connection()
        try:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            conn.commit()
            return cursor
        except sqlite3.Error as e:
            logger.error(f"SQL执行错误: {e}\nQuery: {query}\nParams: {params}")
            raise

    def fetch_one(self, query: str, params: tuple = None) -> Optional[Dict]:
        """
        查询单条记录

        Args:
            query: SQL语句
            params: 参数元组

        Returns:
            dict: 查询结果字典，无结果返回None
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        row = cursor.fetchone()
        return dict(row) if row else None

    def fetch_all(self, query: str, params: tuple = None) -> List[Dict]:
        """
        查询多条记录

        Args:
            query: SQL语句
            params: 参数元组

        Returns:
            list: 查询结果列表
        """
        conn = self.get_connection()
        cursor = conn.cursor()
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]

    def fetch_count(self, table: str, where: str = None, params: tuple = None) -> int:
        """
        查询记录数量

        Args:
            table: 表名
            where: WHERE条件
            params: 参数元组

        Returns:
            int: 记录数量
        """
        query = f"SELECT COUNT(*) as count FROM {table}"
        if where:
            query += f" WHERE {where}"
        result = self.fetch_one(query, params)
        return result['count'] if result else 0


# 全局数据库管理器实例
_db_manager: Optional[DatabaseManager] = None


def init_database(db_path: str = None) -> DatabaseManager:
    """
    初始化数据库

    Args:
        db_path: 数据库文件路径，默认使用配置路径

    Returns:
        DatabaseManager: 数据库管理器实例
    """
    global _db_manager

    if db_path is None:
        from utils.config import Config
        db_path = Config.DATABASE_PATH

    _db_manager = DatabaseManager(db_path)

    # 创建数据表
    _create_tables()

    logger.info(f"数据库初始化完成: {db_path}")
    return _db_manager


def get_db() -> DatabaseManager:
    """
    获取数据库管理器实例

    Returns:
        DatabaseManager: 数据库管理器实例

    Raises:
        RuntimeError: 数据库未初始化
    """
    if _db_manager is None:
        raise RuntimeError("数据库未初始化，请先调用 init_database()")
    return _db_manager


def _create_tables():
    """创建数据库表结构"""

    tables = {
        # 用户表
        'users': '''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(256) NOT NULL,
                salt VARCHAR(64) NOT NULL,
                real_name VARCHAR(50),
                email VARCHAR(100),
                phone VARCHAR(20),
                role_id INTEGER NOT NULL DEFAULT 3,
                department VARCHAR(100),
                position VARCHAR(50),
                status INTEGER DEFAULT 1,
                login_attempts INTEGER DEFAULT 0,
                last_login DATETIME,
                last_login_ip VARCHAR(45),
                password_changed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (role_id) REFERENCES roles(id)
            )
        ''',

        # 角色表
        'roles': '''
            CREATE TABLE IF NOT EXISTS roles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(50) UNIQUE NOT NULL,
                code VARCHAR(50) UNIQUE NOT NULL,
                description VARCHAR(200),
                level INTEGER DEFAULT 0,
                status INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''',

        # 权限表
        'permissions': '''
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name VARCHAR(100) NOT NULL,
                code VARCHAR(100) UNIQUE NOT NULL,
                resource VARCHAR(50) NOT NULL,
                action VARCHAR(20) NOT NULL,
                description VARCHAR(200),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''',

        # 角色权限关联表
        'role_permissions': '''
            CREATE TABLE IF NOT EXISTS role_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_id INTEGER NOT NULL,
                permission_id INTEGER NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
                FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE,
                UNIQUE(role_id, permission_id)
            )
        ''',

        # 敏感数据表
        'sensitive_data': '''
            CREATE TABLE IF NOT EXISTS sensitive_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data_type VARCHAR(50) NOT NULL,
                data_id VARCHAR(100),
                original_data TEXT,
                encrypted_data TEXT,
                masked_data TEXT,
                sensitivity_level INTEGER DEFAULT 1,
                owner_id INTEGER,
                department VARCHAR(100),
                description TEXT,
                status INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                created_by INTEGER,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            )
        ''',

        # 学生信息表
        'students': '''
            CREATE TABLE IF NOT EXISTS students (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id VARCHAR(20) UNIQUE NOT NULL,
                name VARCHAR(50) NOT NULL,
                name_encrypted TEXT,
                gender VARCHAR(10),
                birth_date DATE,
                id_card VARCHAR(18),
                id_card_encrypted TEXT,
                phone VARCHAR(20),
                phone_encrypted TEXT,
                email VARCHAR(100),
                email_encrypted TEXT,
                department VARCHAR(100),
                major VARCHAR(100),
                class_name VARCHAR(50),
                enrollment_date DATE,
                address TEXT,
                address_encrypted TEXT,
                emergency_contact VARCHAR(50),
                emergency_phone VARCHAR(20),
                status INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''',

        # 教职工信息表
        'staff': '''
            CREATE TABLE IF NOT EXISTS staff (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                staff_id VARCHAR(20) UNIQUE NOT NULL,
                name VARCHAR(50) NOT NULL,
                name_encrypted TEXT,
                gender VARCHAR(10),
                birth_date DATE,
                id_card VARCHAR(18),
                id_card_encrypted TEXT,
                phone VARCHAR(20),
                phone_encrypted TEXT,
                email VARCHAR(100),
                email_encrypted TEXT,
                department VARCHAR(100),
                position VARCHAR(50),
                title VARCHAR(50),
                hire_date DATE,
                salary DECIMAL(10,2),
                salary_encrypted TEXT,
                status INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''',

        # 审计日志表
        'audit_logs': '''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username VARCHAR(50),
                action VARCHAR(50) NOT NULL,
                resource VARCHAR(100),
                resource_id VARCHAR(100),
                method VARCHAR(10),
                ip_address VARCHAR(45),
                user_agent TEXT,
                request_url TEXT,
                request_data TEXT,
                response_code INTEGER,
                response_msg TEXT,
                risk_level INTEGER DEFAULT 0,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''',

        # 登录日志表
        'login_logs': '''
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username VARCHAR(50),
                login_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                logout_time DATETIME,
                ip_address VARCHAR(45),
                user_agent TEXT,
                login_status INTEGER DEFAULT 1,
                failure_reason VARCHAR(200),
                session_id VARCHAR(100),
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''',

        # 数据访问记录表
        'data_access_logs': '''
            CREATE TABLE IF NOT EXISTS data_access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                username VARCHAR(50),
                data_type VARCHAR(50),
                data_id INTEGER,
                access_type VARCHAR(20),
                query_condition TEXT,
                result_count INTEGER,
                ip_address VARCHAR(45),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''',

        # 差分隐私查询记录表
        'privacy_queries': '''
            CREATE TABLE IF NOT EXISTS privacy_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                query_type VARCHAR(50),
                query_params TEXT,
                epsilon REAL,
                delta REAL,
                noise_added REAL,
                original_result TEXT,
                noisy_result TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''',

        # 文件加密记录表
        'encrypted_files': '''
            CREATE TABLE IF NOT EXISTS encrypted_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                original_name VARCHAR(255),
                stored_name VARCHAR(255),
                file_path TEXT,
                file_size INTEGER,
                file_type VARCHAR(50),
                encryption_key_id VARCHAR(100),
                checksum VARCHAR(64),
                status INTEGER DEFAULT 1,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''',

        # 系统配置表
        'system_config': '''
            CREATE TABLE IF NOT EXISTS system_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_key VARCHAR(100) UNIQUE NOT NULL,
                config_value TEXT,
                config_type VARCHAR(20),
                description VARCHAR(200),
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_by INTEGER
            )
        ''',

        # 安全事件表
        'security_events': '''
            CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type VARCHAR(50) NOT NULL,
                severity INTEGER DEFAULT 1,
                source VARCHAR(100),
                user_id INTEGER,
                username VARCHAR(50),
                ip_address VARCHAR(45),
                description TEXT,
                raw_data TEXT,
                status INTEGER DEFAULT 0,
                handled_by INTEGER,
                handled_at DATETIME,
                handle_note TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (handled_by) REFERENCES users(id)
            )
        '''
    }

    # 创建索引
    indexes = [
        'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)',
        'CREATE INDEX IF NOT EXISTS idx_users_role_id ON users(role_id)',
        'CREATE INDEX IF NOT EXISTS idx_users_status ON users(status)',
        'CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)',
        'CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_login_logs_user_id ON login_logs(user_id)',
        'CREATE INDEX IF NOT EXISTS idx_login_logs_login_time ON login_logs(login_time)',
        'CREATE INDEX IF NOT EXISTS idx_students_student_id ON students(student_id)',
        'CREATE INDEX IF NOT EXISTS idx_staff_staff_id ON staff(staff_id)',
        'CREATE INDEX IF NOT EXISTS idx_sensitive_data_type ON sensitive_data(data_type)',
        'CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type)',
        'CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at)',
    ]

    db = get_db()

    # 创建表
    for table_name, table_sql in tables.items():
        db.execute(table_sql)
        logger.debug(f"创建表: {table_name}")

    # 创建索引
    for index_sql in indexes:
        db.execute(index_sql)

    logger.info("数据库表结构创建完成")


def get_db_connection() -> sqlite3.Connection:
    """
    获取数据库连接（兼容旧接口）

    Returns:
        sqlite3.Connection: 数据库连接对象
    """
    return get_db().get_connection()


if __name__ == '__main__':
    # 测试数据库初始化
    init_database('test.db')
    print("数据库初始化测试完成")
