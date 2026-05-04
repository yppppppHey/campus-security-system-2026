#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
认证路由模块
处理用户登录、登出、密码修改等认证相关请求
"""

from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from urllib.parse import urlparse

from core.auth import AuthenticationService, User
from core.audit import AuditLogger
from utils.forms import LoginForm, ChangePasswordForm

auth_bp = Blueprint('auth', __name__)
auth_service = AuthenticationService()
audit = AuditLogger()

# 最大登录尝试次数
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=30)


def get_login_status(username):
    """
    获取用户的登录状态信息

    Args:
        username: 用户名

    Returns:
        dict: 登录状态信息，包含锁定状态、失败次数等
    """
    if not username:
        return None

    user = User.get_by_username(username)
    if not user:
        return None

    attempts = user.login_attempts
    if attempts <= 0:
        return None

    # 检查是否锁定
    if attempts >= MAX_LOGIN_ATTEMPTS and user.last_login:
        last_attempt = datetime.fromisoformat(str(user.last_login))
        if datetime.now() - last_attempt < LOCKOUT_DURATION:
            remaining = LOCKOUT_DURATION - (datetime.now() - last_attempt)
            return {
                'locked': True,
                'remaining_minutes': int(remaining.total_seconds() / 60) + 1,
                'attempts': attempts,
                'username': username
            }

    return {
        'locked': False,
        'attempts': attempts,
        'remaining_attempts': MAX_LOGIN_ATTEMPTS - attempts,
        'username': username
    }


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """用户登录"""
    # 已登录用户重定向
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()

    # 获取用户名（从表单或URL参数）
    username = request.form.get('username', '') or request.args.get('username', '')

    # 获取登录状态信息
    login_info = get_login_status(username)

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        remember = form.remember.data

        # 检查账户是否被锁定
        user = User.get_by_username(username)
        if user and user.login_attempts >= MAX_LOGIN_ATTEMPTS and user.last_login:
            last_attempt = datetime.fromisoformat(str(user.last_login))
            if datetime.now() - last_attempt < LOCKOUT_DURATION:
                remaining = LOCKOUT_DURATION - (datetime.now() - last_attempt)
                minutes = int(remaining.total_seconds() / 60) + 1
                # 不使用flash，直接返回页面显示锁定信息
                login_info = {
                    'locked': True,
                    'remaining_minutes': minutes,
                    'attempts': user.login_attempts,
                    'username': username
                }
                return render_template('auth/login.html', form=form, title='用户登录',
                                       login_info=login_info, username=username)

        # 执行登录
        success, user, message = auth_service.login(
            username=username,
            password=password,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )

        if success:
            login_user(user, remember=remember)
            session['user_role'] = user.get_role()['code'] if user.get_role() else 'user'

            # 重定向到目标页面
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('main.index')

            # 登录成功消息在仪表盘显示
            return redirect(next_page)
        else:
            # 登录失败，重新获取状态信息
            login_info = get_login_status(username)

            # 如果账户被锁定，更新状态信息
            if user and user.login_attempts >= MAX_LOGIN_ATTEMPTS:
                last_attempt = datetime.fromisoformat(str(user.last_login))
                if datetime.now() - last_attempt < LOCKOUT_DURATION:
                    remaining = LOCKOUT_DURATION - (datetime.now() - last_attempt)
                    login_info = {
                        'locked': True,
                        'remaining_minutes': int(remaining.total_seconds() / 60) + 1,
                        'attempts': user.login_attempts,
                        'username': username
                    }
                    message = "密码错误次数过多，账户已锁定30分钟"

            return render_template('auth/login.html', form=form, title='用户登录',
                                   login_info=login_info, username=username, error_message=message)

    return render_template('auth/login.html', form=form, title='用户登录',
                           login_info=login_info, username=username)


@auth_bp.route('/api/check-login-status')
def check_login_status():
    """检查用户登录状态的API"""
    username = request.args.get('username', '')
    login_info = get_login_status(username)

    if login_info:
        return jsonify({
            'success': True,
            'has_warning': True,
            'locked': login_info.get('locked', False),
            'attempts': login_info.get('attempts', 0),
            'remaining_attempts': login_info.get('remaining_attempts', 0),
            'remaining_minutes': login_info.get('remaining_minutes', 0),
            'username': username
        })

    return jsonify({
        'success': True,
        'has_warning': False
    })


@auth_bp.route('/logout')
@login_required
def logout():
    """用户登出"""
    # 记录登出日志
    auth_service.logout(
        user_id=current_user.id,
        username=current_user.username,
        ip_address=request.remote_addr
    )

    logout_user()
    session.clear()
    flash('您已成功登出', 'info')
    return redirect(url_for('auth.login'))


@auth_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """修改密码"""
    form = ChangePasswordForm()

    if form.validate_on_submit():
        old_password = form.old_password.data
        new_password = form.new_password.data

        success, message = auth_service.change_password(
            user_id=current_user.id,
            old_password=old_password,
            new_password=new_password
        )

        if success:
            flash(message, 'success')
            return redirect(url_for('main.index'))
        else:
            flash(message, 'danger')

    return render_template('auth/change_password.html', form=form, title='修改密码')


@auth_bp.route('/profile')
@login_required
def profile():
    """用户信息"""
    return render_template('auth/profile.html', title='个人信息')


@auth_bp.route('/api/check-session')
def check_session():
    """检查会话状态"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'user': {
                'id': current_user.id,
                'username': current_user.username,
                'real_name': current_user.real_name,
                'role': current_user.get_role()['name'] if current_user.get_role() else None
            }
        })
    return jsonify({'authenticated': False})