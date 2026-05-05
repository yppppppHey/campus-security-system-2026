#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
面向校园多源敏感数据的一体化安全防护系统
Campus Multi-source Sensitive Data Integrated Security Protection System

作者: 数据安全课程设计
版本: 1.0.0
描述: 实现RBAC权限控制、国密SM4加密、差分隐私、数据脱敏、安全审计的完整系统

主要功能模块:
    - RBAC三角色权限控制系统
    - 国密SM4对称加密存储
    - 差分隐私统计查询
    - 敏感信息动态脱敏
    - 全链路安全审计日志
    - 可视化数据对比图表
    - Flask Web管理界面
"""

import os
import sys
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

from flask import Flask
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect

# 添加项目根目录到路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# 导入核心模块
from core.database import init_database, get_db_connection
from core.auth import User, init_default_users
from core.rbac import RBACManager, init_default_roles_permissions
from core.audit import AuditLogger
from core.encryption import SM4Encryptor
from core.privacy import DifferentialPrivacy
from core.masking import DataMasker
from utils.config import Config
from utils.logger import setup_logger

# 初始化Flask应用
app = Flask(__name__)
app.config.from_object(Config)

# 初始化CSRF保护
csrf = CSRFProtect()
csrf.init_app(app)

# 初始化登录管理器
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'
login_manager.login_message = '请先登录以访问此页面'
login_manager.session_protection = 'strong'

# 初始化RBAC管理器
rbac_manager = RBACManager()

# 初始化审计日志
audit_logger = AuditLogger()

# 初始化加密器
sm4_encryptor = SM4Encryptor(Config.SM4_KEY)

# 初始化差分隐私模块
dp_engine = DifferentialPrivacy(epsilon=Config.DP_EPSILON)

# 初始化数据脱敏器
data_masker = DataMasker()


@login_manager.user_loader
def load_user(user_id):
    """加载用户回调函数"""
    return User.get(user_id)


def create_app():
    """应用工厂函数"""
    # 设置日志
    setup_logger(app)

    # 确保必要目录存在
    ensure_directories()

    # 初始化数据库
    init_database()

    # 初始化默认用户和角色
    init_default_users()
    init_default_roles_permissions()

    # 注册蓝图
    from app.routes.auth import auth_bp
    from app.routes.main import main_bp
    from app.routes.admin import admin_bp
    from app.routes.api import api_bp
    from app.routes.data import data_bp
    from app.routes.sef_api import sef_api

    # 豁免SEF API的CSRF保护（必须在蓝图注册之前）
    csrf.exempt(sef_api)

    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(main_bp)
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(data_bp, url_prefix='/data')
    app.register_blueprint(sef_api, url_prefix='/api/sef')

    # 为差分隐私API路由豁免CSRF保护
    csrf.exempt(app.view_functions['data.api_privacy_query'])
    csrf.exempt(app.view_functions['data.api_privacy_compare'])

    # 打印豁免信息
    app.logger.info(f'CSRF豁免蓝图: {csrf._exempt_blueprints}')
    app.logger.info(f'CSRF豁免视图: {csrf._exempt_views}')

    # 注册模板过滤器
    register_template_filters()

    # 注册上下文处理器
    register_context_processors()

    app.logger.info('校园敏感数据安全防护系统启动成功')

    return app


def ensure_directories():
    """确保必要目录存在"""
    directories = [
        Config.LOG_DIR,
        Config.DATA_DIR,
        Config.UPLOAD_DIR,
        Config.EXPORT_DIR
    ]
    for directory in directories:
        os.makedirs(directory, exist_ok=True)


def register_template_filters():
    """注册Jinja2模板过滤器"""

    @app.template_filter('datetime')
    def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
        """日期时间格式化过滤器"""
        if value is None:
            return ''
        if isinstance(value, str):
            try:
                value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return value
        return value.strftime(format)

    @app.template_filter('mask_id_card')
    def mask_id_card(value):
        """身份证号脱敏过滤器"""
        return data_masker.mask_id_card(str(value)) if value else ''

    @app.template_filter('mask_phone')
    def mask_phone(value):
        """手机号脱敏过滤器"""
        return data_masker.mask_phone(str(value)) if value else ''

    @app.template_filter('mask_email')
    def mask_email(value):
        """邮箱脱敏过滤器"""
        return data_masker.mask_email(str(value)) if value else ''

    @app.template_filter('mask_name')
    def mask_name(value):
        """姓名脱敏过滤器"""
        return data_masker.mask_name(str(value)) if value else ''


def register_context_processors():
    """注册上下文处理器"""

    @app.context_processor
    def inject_now():
        """注入当前时间"""
        return {'now': datetime.now()}

    @app.context_processor
    def inject_config():
        """注入配置"""
        return {'config': Config}


# 错误处理器
@app.errorhandler(403)
def forbidden(e):
    """403错误处理"""
    from flask import render_template, request
    print(f'DEBUG: request.endpoint={request.endpoint}, request.blueprint={request.blueprint}')
    return render_template('errors/403.html'), 403


@app.errorhandler(404)
def page_not_found(e):
    """404错误处理"""
    from flask import render_template
    return render_template('errors/404.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    """500错误处理"""
    from flask import render_template
    app.logger.error(f'服务器内部错误: {e}')
    return render_template('errors/500.html'), 500


@app.errorhandler(Exception)
def handle_exception(e):
    """全局异常处理"""
    from flask import render_template, request
    app.logger.error(f'未处理的异常: {e}')
    app.logger.error(f'request.endpoint={request.endpoint}, request.blueprint={request.blueprint}')
    app.logger.error(f'app.blueprints={list(app.blueprints.keys())}')
    app.logger.error(f'csrf._exempt_blueprints={csrf._exempt_blueprints}')
    return render_template('errors/500.html'), 500


# 创建应用实例
application = create_app()


if __name__ == '__main__':
    application.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=False,  # 禁用debug模式避免reloader问题
        threaded=True
    )