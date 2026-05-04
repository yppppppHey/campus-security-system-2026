#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
系统启动脚本
初始化数据库、生成测试数据、启动Web服务
"""

import os
import sys
import argparse

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.config import Config
from utils.helpers import generate_test_data


def init_system():
    """初始化系统"""
    print("=" * 60)
    print("校园多源敏感数据一体化安全防护系统")
    print("Campus Multi-source Sensitive Data Integrated Security Protection System")
    print("=" * 60)
    print()

    # 确保必要目录存在
    directories = [
        Config.LOG_DIR,
        Config.DATA_DIR,
        Config.UPLOAD_DIR,
        Config.EXPORT_DIR
    ]

    for directory in directories:
        if not os.path.exists(directory):
            os.makedirs(directory)
            print(f"创建目录: {directory}")

    # 初始化数据库
    print("\n正在初始化数据库...")
    from core.database import init_database
    init_database()

    # 初始化角色和权限
    print("正在初始化角色和权限...")
    from core.rbac import init_default_roles_permissions
    init_default_roles_permissions()

    # 初始化默认用户
    print("正在初始化默认用户...")
    from core.auth import init_default_users
    init_default_users()

    # 生成测试数据
    print("正在生成测试数据...")
    generate_test_data()

    print("\n系统初始化完成！")
    print()


def run_server(host=None, port=None, debug=None):
    """启动Web服务器"""
    # 直接导入 app.py 模块，避免与 app/ 包冲突
    import importlib.util
    app_module_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app.py')
    spec = importlib.util.spec_from_file_location("flask_app", app_module_path)
    flask_app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(flask_app)
    application = flask_app.application

    host = host or Config.HOST
    port = port or Config.PORT
    debug = debug if debug is not None else Config.DEBUG

    print(f"\n启动Web服务器: http://{host}:{port}")
    print("按 Ctrl+C 停止服务器\n")

    application.run(
        host=host,
        port=port,
        debug=debug,
        threaded=True
    )


def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description='校园多源敏感数据一体化安全防护系统'
    )

    parser.add_argument(
        '--init',
        action='store_true',
        help='初始化系统（创建数据库、默认用户、测试数据）'
    )

    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='服务器监听地址（默认: 127.0.0.1）'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='服务器监听端口（默认: 5000）'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='启用调试模式'
    )

    parser.add_argument(
        '--no-init',
        action='store_true',
        help='跳过初始化直接启动'
    )

    args = parser.parse_args()

    if args.init:
        init_system()
    elif not args.no_init:
        # 默认执行初始化
        try:
            init_system()
        except Exception as e:
            print(f"初始化警告: {e}")
            print("尝试直接启动服务器...")

    run_server(
        host=args.host,
        port=args.port,
        debug=args.debug
    )


if __name__ == '__main__':
    main()