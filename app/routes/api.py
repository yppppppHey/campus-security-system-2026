#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
API接口路由模块
提供RESTful API接口供前端调用
"""

from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify
from flask_login import login_required, current_user

from core.database import get_db
from core.rbac import permission_required, api_permission_required
from core.audit import AuditLogger
from core.masking import DataMasker
from core.privacy import DifferentialPrivacy

api_bp = Blueprint('api', __name__)
audit = AuditLogger()
masker = DataMasker()


# ==================== 用户API ====================

@api_bp.route('/users')
@login_required
@api_permission_required('user:view')
def get_users():
    """获取用户列表"""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    search = request.args.get('search', '')

    offset = (page - 1) * per_page

    conditions = []
    params = []

    if search:
        conditions.append("(username LIKE ? OR real_name LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    total = db.fetch_one(f"SELECT COUNT(*) as count FROM users WHERE {where_clause}", tuple(params))['count']

    query = f"""
        SELECT u.id, u.username, u.real_name, u.email, u.phone,
               u.department, u.position, u.status, u.last_login,
               r.name as role_name
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE {where_clause}
        ORDER BY u.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    users = db.fetch_all(query, tuple(params))

    return jsonify({
        'success': True,
        'data': users,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    })


@api_bp.route('/users/<int:user_id>')
@login_required
@api_permission_required('user:view')
def get_user(user_id):
    """获取用户详情"""
    db = get_db()

    user = db.fetch_one(
        """
        SELECT u.*, r.name as role_name, r.code as role_code
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE u.id = ?
        """,
        (user_id,)
    )

    if not user:
        return jsonify({'success': False, 'error': '用户不存在'}), 404

    # 移除敏感字段
    user.pop('password_hash', None)
    user.pop('salt', None)

    return jsonify({
        'success': True,
        'data': user
    })


# ==================== 数据统计API ====================

@api_bp.route('/stats/overview')
@login_required
def stats_overview():
    """获取系统概览统计"""
    db = get_db()

    stats = {
        'users': {
            'total': db.fetch_count('users', 'status = 1'),
            'admins': db.fetch_count('users', 'role_id = 1'),
            'active_today': db.fetch_count(
                'login_logs',
                "date(login_time) = date('now') AND login_status = 1"
            )
        },
        'data': {
            'students': db.fetch_count('students'),
            'staff': db.fetch_count('staff'),
            'encrypted_files': db.fetch_count('encrypted_files')
        },
        'security': {
            'pending_events': db.fetch_count('security_events', 'status = 0'),
            'high_risk_events': db.fetch_count('security_events', 'severity >= 3 AND status = 0'),
            'failed_logins_today': db.fetch_count(
                'login_logs',
                "date(login_time) = date('now') AND login_status = 0"
            )
        }
    }

    return jsonify({
        'success': True,
        'data': stats
    })


@api_bp.route('/stats/login-trend')
@login_required
def stats_login_trend():
    """获取登录趋势"""
    db = get_db()

    days = request.args.get('days', 7, type=int)
    trend = []

    for i in range(days - 1, -1, -1):
        date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        success = db.fetch_count(
            'login_logs',
            "date(login_time) = ? AND login_status = 1",
            (date,)
        )
        fail = db.fetch_count(
            'login_logs',
            "date(login_time) = ? AND login_status = 0",
            (date,)
        )
        trend.append({
            'date': date,
            'success': success,
            'fail': fail
        })

    return jsonify({
        'success': True,
        'data': trend
    })


@api_bp.route('/stats/data-access')
@login_required
def stats_data_access():
    """获取数据访问统计"""
    db = get_db()

    days = request.args.get('days', 30, type=int)
    start_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')

    stats = db.fetch_all(
        """
        SELECT data_type, access_type, COUNT(*) as count
        FROM data_access_logs
        WHERE date(created_at) >= ?
        GROUP BY data_type, access_type
        ORDER BY count DESC
        """,
        (start_date,)
    )

    return jsonify({
        'success': True,
        'data': stats
    })


# ==================== 审计日志API ====================

@api_bp.route('/audit/logs')
@login_required
@api_permission_required('audit:view')
def audit_logs():
    """获取审计日志"""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    user_id = request.args.get('user_id', type=int)
    action = request.args.get('action', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')

    offset = (page - 1) * per_page

    conditions = []
    params = []

    if user_id:
        conditions.append("user_id = ?")
        params.append(user_id)

    if action:
        conditions.append("action LIKE ?")
        params.append(f'%{action}%')

    if start_date:
        conditions.append("date(created_at) >= ?")
        params.append(start_date)

    if end_date:
        conditions.append("date(created_at) <= ?")
        params.append(end_date)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    total = db.fetch_one(f"SELECT COUNT(*) as count FROM audit_logs WHERE {where_clause}", tuple(params))['count']

    query = f"""
        SELECT * FROM audit_logs
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    logs = db.fetch_all(query, tuple(params))

    return jsonify({
        'success': True,
        'data': logs,
        'pagination': {
            'page': page,
            'per_page': per_page,
            'total': total,
            'pages': (total + per_page - 1) // per_page
        }
    })


@api_bp.route('/audit/analysis')
@login_required
@api_permission_required('audit:analyze')
def audit_analysis():
    """获取审计分析结果"""
    analysis = audit.analyze_security_events(hours=24)

    return jsonify({
        'success': True,
        'data': analysis
    })


# ==================== 差分隐私API ====================

@api_bp.route('/privacy/demo')
@login_required
def privacy_demo():
    """差分隐私演示数据"""
    db = get_db()

    # 获取真实数据统计
    true_stats = {
        'student_count': db.fetch_count('students'),
        'staff_count': db.fetch_count('staff'),
        'department_counts': {}
    }

    # 各院系人数
    dept_counts = db.fetch_all(
        "SELECT department, COUNT(*) as count FROM students GROUP BY department"
    )
    true_stats['department_counts'] = {d['department']: d['count'] for d in dept_counts}

    # 应用差分隐私
    dp = DifferentialPrivacy(epsilon=1.0)

    noisy_stats = {
        'student_count': dp.noisy_count(true_stats['student_count']),
        'staff_count': dp.noisy_count(true_stats['staff_count']),
        'department_counts': {}
    }

    for dept, count in true_stats['department_counts'].items():
        noisy_stats['department_counts'][dept] = dp.noisy_count(count)

    # 计算误差
    errors = {
        'student_count': {
            'absolute': abs(noisy_stats['student_count'] - true_stats['student_count']),
            'relative': abs(noisy_stats['student_count'] - true_stats['student_count']) / true_stats['student_count'] if true_stats['student_count'] > 0 else 0
        }
    }

    return jsonify({
        'success': True,
        'data': {
            'true': true_stats,
            'noisy': noisy_stats,
            'errors': errors,
            'epsilon': dp.epsilon
        }
    })


@api_bp.route('/privacy/epsilon-comparison')
@login_required
def epsilon_comparison():
    """不同epsilon值的对比"""
    db = get_db()

    true_count = db.fetch_count('students')

    results = []
    for epsilon in [0.1, 0.5, 1.0, 2.0, 5.0]:
        dp = DifferentialPrivacy(epsilon=epsilon)
        noisy_counts = [dp.noisy_count(true_count) for _ in range(10)]

        avg_noisy = sum(noisy_counts) / len(noisy_counts)
        avg_error = abs(avg_noisy - true_count)

        results.append({
            'epsilon': epsilon,
            'true_count': true_count,
            'noisy_counts': noisy_counts,
            'average': avg_noisy,
            'average_error': avg_error,
            'relative_error': avg_error / true_count if true_count > 0 else 0
        })

    return jsonify({
        'success': True,
        'data': results
    })


# ==================== 脱敏演示API ====================

@api_bp.route('/masking/demo')
@login_required
def masking_demo():
    """数据脱敏演示"""
    demo_data = {
        'id_card': '320102199001011234',
        'phone': '13812345678',
        'email': 'zhangsan@example.com',
        'name': '张三',
        'bank_card': '6222021234567890123',
        'address': '江苏省南京市玄武区北京东路1号',
        'ip': '192.168.1.100'
    }

    masked_data = {
        'id_card': masker.mask_id_card(demo_data['id_card']),
        'phone': masker.mask_phone(demo_data['phone']),
        'email': masker.mask_email(demo_data['email']),
        'name': masker.mask_name(demo_data['name']),
        'bank_card': masker.mask_bank_card(demo_data['bank_card']),
        'address': masker.mask_address(demo_data['address']),
        'ip': masker.mask_ip_address(demo_data['ip'])
    }

    return jsonify({
        'success': True,
        'data': {
            'original': demo_data,
            'masked': masked_data
        }
    })


# ==================== 系统健康检查API ====================

@api_bp.route('/health')
def health_check():
    """系统健康检查"""
    try:
        db = get_db()
        # 测试数据库连接
        db.fetch_one("SELECT 1")

        return jsonify({
            'success': True,
            'status': 'healthy',
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500


@api_bp.route('/version')
def version():
    """获取系统版本信息"""
    return jsonify({
        'success': True,
        'version': '1.0.0',
        'name': '校园多源敏感数据一体化安全防护系统',
        'features': [
            'RBAC权限控制',
            '国密SM4加密',
            '差分隐私保护',
            '敏感数据脱敏',
            '安全审计日志'
        ]
    })