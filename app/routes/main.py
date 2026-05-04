#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
主路由模块
处理首页、仪表盘等主要页面请求
"""

from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user

from core.database import get_db
from core.rbac import permission_required
from core.audit import AuditLogger

main_bp = Blueprint('main', __name__)
audit = AuditLogger()


@main_bp.route('/')
def index():
    """首页"""
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    return redirect(url_for('main.dashboard'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """仪表盘"""
    db = get_db()

    # 获取统计数据
    stats = {}

    # 用户统计
    stats['total_users'] = db.fetch_count('users', 'status = 1')

    # 数据统计
    stats['total_students'] = db.fetch_count('students')
    stats['total_staff'] = db.fetch_count('staff')

    # 今日登录次数
    today = datetime.now().strftime('%Y-%m-%d')
    stats['today_logins'] = db.fetch_count(
        'login_logs',
        "date(login_time) = ? AND login_status = 1",
        (today,)
    )

    # 安全事件统计
    stats['pending_events'] = db.fetch_count('security_events', 'status = 0')

    # 最近登录日志
    recent_logins = db.fetch_all(
        """
        SELECT ll.*, u.real_name
        FROM login_logs ll
        LEFT JOIN users u ON ll.user_id = u.id
        WHERE ll.login_status = 1
        ORDER BY ll.login_time DESC
        LIMIT 10
        """
    )

    # 最近操作日志
    recent_audits = db.fetch_all(
        """
        SELECT * FROM audit_logs
        ORDER BY created_at DESC
        LIMIT 10
        """
    )

    # 登录趋势（最近7天）
    login_trend = []
    for i in range(6, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        count = db.fetch_count(
            'login_logs',
            "date(login_time) = ? AND login_status = 1",
            (date,)
        )
        login_trend.append({
            'date': date,
            'count': count
        })

    # 数据访问统计
    access_stats = db.fetch_all(
        """
        SELECT data_type, COUNT(*) as count
        FROM data_access_logs
        WHERE date(created_at) >= date('now', '-7 days')
        GROUP BY data_type
        ORDER BY count DESC
        """
    )

    return render_template('main/dashboard.html',
                           stats=stats,
                           recent_logins=recent_logins,
                           recent_audits=recent_audits,
                           login_trend=login_trend,
                           access_stats=access_stats,
                           title='系统仪表盘')


@main_bp.route('/about')
@login_required
def about():
    """关于页面"""
    return render_template('main/about.html', title='关于系统')


@main_bp.route('/help')
@login_required
def help():
    """帮助页面"""
    return render_template('main/help.html', title='帮助中心')


@main_bp.route('/search')
@login_required
def search():
    """全局搜索"""
    keyword = request.args.get('q', '').strip()

    if not keyword:
        return render_template('main/search.html', results=None, title='搜索')

    db = get_db()
    results = {
        'users': [],
        'students': [],
        'staff': [],
        'logs': []
    }

    # 搜索用户
    if current_user.has_permission('user:view'):
        results['users'] = db.fetch_all(
            """
            SELECT id, username, real_name, email, department
            FROM users
            WHERE username LIKE ? OR real_name LIKE ? OR email LIKE ?
            LIMIT 10
            """,
            (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%')
        )

    # 搜索学生
    if current_user.has_permission('data:view'):
        results['students'] = db.fetch_all(
            """
            SELECT id, student_id, name, department, major
            FROM students
            WHERE student_id LIKE ? OR name LIKE ?
            LIMIT 10
            """,
            (f'%{keyword}%', f'%{keyword}%')
        )

    # 搜索教职工
    if current_user.has_permission('data:view'):
        results['staff'] = db.fetch_all(
            """
            SELECT id, staff_id, name, department, position
            FROM staff
            WHERE staff_id LIKE ? OR name LIKE ?
            LIMIT 10
            """,
            (f'%{keyword}%', f'%{keyword}%')
        )

    return render_template('main/search.html',
                           keyword=keyword,
                           results=results,
                           title='搜索结果')


@main_bp.route('/api/stats')
@login_required
def api_stats():
    """获取统计数据API"""
    db = get_db()

    # 时间范围
    days = request.args.get('days', 7, type=int)

    stats = {
        'users': db.fetch_count('users', 'status = 1'),
        'students': db.fetch_count('students'),
        'staff': db.fetch_count('staff'),
        'today_logins': db.fetch_count(
            'login_logs',
            "date(login_time) = date('now') AND login_status = 1"
        ),
        'pending_events': db.fetch_count('security_events', 'status = 0')
    }

    return jsonify(stats)


@main_bp.route('/api/chart/login-trend')
@login_required
def chart_login_trend():
    """登录趋势图表数据"""
    db = get_db()

    days = request.args.get('days', 7, type=int)
    trend = []

    for i in range(days - 1, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        success_count = db.fetch_count(
            'login_logs',
            "date(login_time) = ? AND login_status = 1",
            (date,)
        )
        fail_count = db.fetch_count(
            'login_logs',
            "date(login_time) = ? AND login_status = 0",
            (date,)
        )
        trend.append({
            'date': date,
            'success': success_count,
            'fail': fail_count
        })

    return jsonify(trend)


@main_bp.route('/api/chart/access-distribution')
@login_required
def chart_access_distribution():
    """数据访问分布图表"""
    db = get_db()

    distribution = db.fetch_all(
        """
        SELECT data_type, COUNT(*) as count
        FROM data_access_logs
        WHERE date(created_at) >= date('now', '-30 days')
        GROUP BY data_type
        ORDER BY count DESC
        """
    )

    return jsonify(distribution)