#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
日志配置模块
配置系统日志输出
"""

import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime


def setup_logger(app):
    """
    配置应用日志

    Args:
        app: Flask应用实例
    """
    # 创建日志目录
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'logs')
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # 设置日志级别
    log_level = logging.DEBUG if app.debug else logging.INFO

    # 文件处理器
    file_handler = RotatingFileHandler(
        os.path.join(log_dir, 'app.log'),
        maxBytes=10 * 1024 * 1024,  # 10MB
        backupCount=10,
        encoding='utf-8'
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(log_level)

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s [%(name)s] %(message)s'
    ))
    console_handler.setLevel(log_level)

    # 配置根日志器
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

    # 配置应用日志器
    app.logger.addHandler(file_handler)
    app.logger.setLevel(log_level)

    # 配置第三方库日志级别
    logging.getLogger('werkzeug').setLevel(logging.WARNING)
    logging.getLogger('sqlalchemy').setLevel(logging.WARNING)

    app.logger.info(f'日志系统初始化完成: {log_dir}')


def get_logger(name: str) -> logging.Logger:
    """
    获取日志器

    Args:
        name: 日志器名称

    Returns:
        logging.Logger: 日志器实例
    """
    return logging.getLogger(name)