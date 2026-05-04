# 工具模块包
"""
校园安全防护系统工具模块

包含:
    - config: 系统配置
    - logger: 日志配置
    - forms: 表单定义
    - helpers: 辅助函数
"""

from .config import Config, DevelopmentConfig, ProductionConfig, TestingConfig
from .logger import setup_logger, get_logger
from .forms import LoginForm, ChangePasswordForm, UserForm, StudentForm, SearchForm
from .helpers import (
    generate_test_data,
    format_datetime,
    format_date,
    generate_random_string,
    validate_id_card,
    validate_phone,
    validate_email,
    get_client_ip,
    paginate
)

__all__ = [
    'Config',
    'DevelopmentConfig',
    'ProductionConfig',
    'TestingConfig',
    'setup_logger',
    'get_logger',
    'LoginForm',
    'ChangePasswordForm',
    'UserForm',
    'StudentForm',
    'SearchForm',
    'generate_test_data',
    'format_datetime',
    'format_date',
    'generate_random_string',
    'validate_id_card',
    'validate_phone',
    'validate_email',
    'get_client_ip',
    'paginate'
]