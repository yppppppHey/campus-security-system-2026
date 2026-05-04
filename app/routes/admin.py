#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
管理后台路由模块
处理用户管理、角色管理、系统配置等管理功能
"""

from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import login_required, current_user

from core.database import get_db
from core.auth import User, AuthenticationService, PasswordHasher, PasswordValidator
from core.rbac import RBACManager, permission_required, role_required
from core.audit import AuditLogger, RiskLevel

admin_bp = Blueprint('admin', __name__)
rbac = RBACManager()
audit = AuditLogger()
auth_service = AuthenticationService()


# ==================== 用户管理 ====================

@admin_bp.route('/users')
@login_required
@permission_required('user:view')
def users():
    """用户列表"""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    # 搜索条件
    search = request.args.get('search', '')
    role_filter = request.args.get('role', '')
    status_filter = request.args.get('status', '')

    conditions = []
    params = []

    if search:
        conditions.append("(username LIKE ? OR real_name LIKE ? OR email LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])

    if role_filter:
        conditions.append("role_id = ?")
        params.append(int(role_filter))

    if status_filter:
        conditions.append("status = ?")
        params.append(int(status_filter))

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # 获取总数
    count_query = f"SELECT COUNT(*) as count FROM users WHERE {where_clause}"
    total = db.fetch_one(count_query, tuple(params))['count']

    # 获取用户列表
    query = f"""
        SELECT u.*, r.name as role_name, r.code as role_code
        FROM users u
        LEFT JOIN roles r ON u.role_id = r.id
        WHERE {where_clause}
        ORDER BY u.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    users_list = db.fetch_all(query, tuple(params))

    # 获取所有角色
    roles = rbac.get_all_roles()

    return render_template('admin/users.html',
                           users=users_list,
                           roles=roles,
                           page=page,
                           total=total,
                           per_page=per_page,
                           search=search,
                           role_filter=role_filter,
                           status_filter=status_filter,
                           title='用户管理')


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@permission_required('user:create')
def create_user():
    """创建用户"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        real_name = request.form.get('real_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        department = request.form.get('department')
        position = request.form.get('position')

        db = get_db()

        # 检查用户名是否存在
        existing = db.fetch_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            flash('用户名已存在', 'danger')
            return redirect(url_for('admin.create_user'))

        # 验证密码强度
        validator = PasswordValidator()
        valid, errors = validator.validate(password)
        if not valid:
            flash('密码不符合要求: ' + '; '.join(errors), 'danger')
            return redirect(url_for('admin.create_user'))

        # 创建用户
        salt = PasswordHasher.generate_salt()
        password_hash = PasswordHasher.hash_password(password, salt)

        db.execute(
            """
            INSERT INTO users
            (username, password_hash, salt, real_name, email, phone, role_id, department, position, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
            """,
            (username, password_hash, salt, real_name, email, phone, role_id, department, position, current_user.id)
        )

        # 记录审计日志
        audit.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='create_user',
            resource='user',
            resource_id=username,
            ip_address=request.remote_addr,
            risk_level=RiskLevel.MEDIUM,
            details=f'创建用户: {username}'
        )

        flash('用户创建成功', 'success')
        return redirect(url_for('admin.users'))

    roles = rbac.get_all_roles()
    return render_template('admin/user_form.html', roles=roles, title='创建用户')


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('user:update')
def edit_user(user_id):
    """编辑用户"""
    db = get_db()

    user = db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('admin.users'))

    if request.method == 'POST':
        real_name = request.form.get('real_name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        role_id = request.form.get('role_id')
        department = request.form.get('department')
        position = request.form.get('position')
        status = request.form.get('status', 1)

        db.execute(
            """
            UPDATE users SET
                real_name = ?, email = ?, phone = ?, role_id = ?,
                department = ?, position = ?, status = ?, updated_at = ?
            WHERE id = ?
            """,
            (real_name, email, phone, role_id, department, position, status, datetime.now(), user_id)
        )

        audit.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='update_user',
            resource='user',
            resource_id=str(user_id),
            ip_address=request.remote_addr,
            details=f'更新用户信息: {user["username"]}'
        )

        flash('用户信息更新成功', 'success')
        return redirect(url_for('admin.users'))

    roles = rbac.get_all_roles()
    return render_template('admin/user_form.html', user=user, roles=roles, title='编辑用户')


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@permission_required('user:delete')
def delete_user(user_id):
    """删除用户"""
    db = get_db()

    user = db.fetch_one("SELECT * FROM users WHERE id = ?", (user_id,))
    if not user:
        flash('用户不存在', 'danger')
        return redirect(url_for('admin.users'))

    # 不能删除自己
    if user_id == current_user.id:
        flash('不能删除自己的账户', 'danger')
        return redirect(url_for('admin.users'))

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))

    audit.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action='delete_user',
        resource='user',
        resource_id=str(user_id),
        ip_address=request.remote_addr,
        risk_level=RiskLevel.HIGH,
        details=f'删除用户: {user["username"]}'
    )

    flash('用户已删除', 'success')
    return redirect(url_for('admin.users'))


@admin_bp.route('/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
@permission_required('user:reset_password')
def reset_user_password(user_id):
    """重置用户密码"""
    new_password = request.form.get('new_password')

    success, message = auth_service.reset_password(user_id, new_password, current_user.id)

    if success:
        audit.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='reset_password',
            resource='user',
            resource_id=str(user_id),
            ip_address=request.remote_addr,
            risk_level=RiskLevel.HIGH,
            details='重置用户密码'
        )
        flash(message, 'success')
    else:
        flash(message, 'danger')

    return redirect(url_for('admin.edit_user', user_id=user_id))


# ==================== 角色管理 ====================

@admin_bp.route('/roles')
@login_required
@permission_required('role:view')
def roles():
    """角色列表"""
    roles_list = rbac.get_all_roles()

    # 获取每个角色的用户数量
    db = get_db()
    for role in roles_list:
        role['user_count'] = db.fetch_count('users', 'role_id = ?', (role['id'],))

    return render_template('admin/roles.html', roles=roles_list, title='角色管理')


@admin_bp.route('/roles/<int:role_id>')
@login_required
@permission_required('role:view')
def role_detail(role_id):
    """角色详情"""
    role = rbac.get_role(role_id)
    if not role:
        flash('角色不存在', 'danger')
        return redirect(url_for('admin.roles'))

    permissions = rbac.get_role_permissions(role_id)
    all_permissions = rbac.get_all_permissions()

    return render_template('admin/role_detail.html',
                           role=role,
                           permissions=permissions,
                           all_permissions=all_permissions,
                           title='角色详情')


@admin_bp.route('/roles/<int:role_id>/permissions', methods=['POST'])
@login_required
@permission_required('role:update')
def update_role_permissions(role_id):
    """更新角色权限"""
    permission_ids = request.form.getlist('permissions')
    permission_ids = [int(pid) for pid in permission_ids]

    success, message = rbac.assign_permissions(role_id, permission_ids)

    if success:
        audit.log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='update_role_permissions',
            resource='role',
            resource_id=str(role_id),
            ip_address=request.remote_addr,
            risk_level=RiskLevel.HIGH,
            details=f'更新角色权限: {len(permission_ids)}个权限'
        )
        flash(message, 'success')
    else:
        flash(message, 'danger')

    return redirect(url_for('admin.role_detail', role_id=role_id))


# ==================== 系统配置 ====================

@admin_bp.route('/settings')
@login_required
@permission_required('system:config')
def settings():
    """系统设置"""
    db = get_db()

    configs = db.fetch_all("SELECT * FROM system_config ORDER BY config_key")

    return render_template('admin/settings.html', configs=configs, title='系统设置')


@admin_bp.route('/settings/update', methods=['POST'])
@login_required
@permission_required('system:config')
def update_settings():
    """更新系统设置"""
    db = get_db()

    for key, value in request.form.items():
        if key.startswith('config_'):
            config_key = key[7:]  # 去掉 'config_' 前缀
            db.execute(
                """
                INSERT INTO system_config (config_key, config_value, updated_at, updated_by)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(config_key) DO UPDATE SET
                    config_value = excluded.config_value,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (config_key, value, datetime.now(), current_user.id)
            )

    audit.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action='update_settings',
        resource='system',
        ip_address=request.remote_addr,
        risk_level=RiskLevel.MEDIUM,
        details='更新系统配置'
    )

    flash('系统设置已更新', 'success')
    return redirect(url_for('admin.settings'))


# ==================== 安全事件管理 ====================

@admin_bp.route('/security-events')
@login_required
@permission_required('security:view')
def security_events():
    """安全事件列表"""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    # 筛选条件
    event_type = request.args.get('event_type', '')
    severity = request.args.get('severity', '')
    status = request.args.get('status', '')

    conditions = []
    params = []

    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    if severity:
        conditions.append("severity = ?")
        params.append(int(severity))

    if status:
        conditions.append("status = ?")
        params.append(int(status))

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # 获取总数
    count_query = f"SELECT COUNT(*) as count FROM security_events WHERE {where_clause}"
    total = db.fetch_one(count_query, tuple(params))['count']

    # 获取事件列表
    query = f"""
        SELECT se.*, u.real_name as handler_name
        FROM security_events se
        LEFT JOIN users u ON se.handled_by = u.id
        WHERE {where_clause}
        ORDER BY se.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    events = db.fetch_all(query, tuple(params))

    return render_template('admin/security_events.html',
                           events=events,
                           page=page,
                           total=total,
                           per_page=per_page,
                           event_type=event_type,
                           severity=severity,
                           status=status,
                           title='安全事件')


@admin_bp.route('/security-events/<int:event_id>/handle', methods=['POST'])
@login_required
@permission_required('security:handle')
def handle_security_event(event_id):
    """处理安全事件"""
    db = get_db()

    handle_note = request.form.get('handle_note', '')

    db.execute(
        """
        UPDATE security_events SET
            status = 1,
            handled_by = ?,
            handled_at = ?,
            handle_note = ?
        WHERE id = ?
        """,
        (current_user.id, datetime.now(), handle_note, event_id)
    )

    audit.log_action(
        user_id=current_user.id,
        username=current_user.username,
        action='handle_security_event',
        resource='security',
        resource_id=str(event_id),
        ip_address=request.remote_addr,
        details=f'处理安全事件: {handle_note}'
    )

    flash('安全事件已处理', 'success')
    return redirect(url_for('admin.security_events'))