#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
系统配置模块
定义系统运行所需的各项配置参数
"""

import os
import secrets
from datetime import timedelta


class Config:
    """系统配置类"""

    # 基础配置 - 项目根目录
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # 使用固定的SECRET_KEY，确保session在重启后保持有效
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'campus_security_system_secret_key_2024_fixed'

    # 模板配置
    TEMPLATES_AUTO_RELOAD = True

    # 数据库配置
    DATABASE_PATH = os.path.join(BASE_DIR, 'data', 'campus_security.db')
    DATABASE_URI = f'sqlite:///{DATABASE_PATH}'

    # 会话配置
    SESSION_COOKIE_SECURE = False  # 开发环境设为False，生产环境设为True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2)

    # CSRF配置
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600  # 1小时，单位为秒

    # 文件上传配置
    UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'json', 'xlsx', 'pdf'}

    # 日志配置
    LOG_DIR = os.path.join(BASE_DIR, 'logs')
    LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = 5

    # 数据目录
    DATA_DIR = os.path.join(BASE_DIR, 'data')
    EXPORT_DIR = os.path.join(BASE_DIR, 'exports')

    # SM4加密配置
    # 128位密钥(32个十六进制字符)
    SM4_KEY = os.environ.get('SM4_KEY') or '0123456789abcdeffedcba9876543210'

    # 差分隐私配置
    DP_EPSILON = 1.0  # 隐私预算
    DP_DELTA = 1e-5   # 失败概率

    # 审计日志配置
    AUDIT_LOG_FILE = os.path.join(LOG_DIR, 'audit.log')
    AUDIT_LOG_MAX_SIZE = 50 * 1024 * 1024  # 50MB
    AUDIT_LOG_BACKUP = 10

    # 密码安全配置
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_AGE_DAYS = 90
    PASSWORD_HISTORY_COUNT = 5

    # 登录安全配置
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_LOCKOUT_DURATION = timedelta(minutes=30)

    # 服务器配置
    HOST = '127.0.0.1'
    PORT = 5001  # 使用不同端口避免冲突
    DEBUG = True

    # 邮件配置(用于通知)
    MAIL_SERVER = 'smtp.example.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = ''
    MAIL_PASSWORD = ''

    # 分页配置
    ITEMS_PER_PAGE = 20

    @staticmethod
    def init_app():
        """初始化应用配置"""
        # 确保必要目录存在
        os.makedirs(Config.LOG_DIR, exist_ok=True)
        os.makedirs(Config.DATA_DIR, exist_ok=True)
        os.makedirs(Config.UPLOAD_DIR, exist_ok=True)
        os.makedirs(Config.EXPORT_DIR, exist_ok=True)


class DevelopmentConfig(Config):
    """开发环境配置"""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """生产环境配置"""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True

    # 生产环境必须设置密钥
    @classmethod
    def init_app(cls):
        Config.init_app()
        assert cls.SECRET_KEY != os.environ.get('SECRET_KEY') or \
               '生产环境必须设置SECRET_KEY环境变量'


class TestingConfig(Config):
    """测试环境配置"""
    TESTING = True
    WTF_CSRF_ENABLED = False
    DATABASE_PATH = ':memory:'


# 配置映射
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
