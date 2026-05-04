#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据管理路由模块
处理学生数据、教职工数据、敏感数据的管理
"""

import os
import csv
import json
from datetime import datetime
from io import StringIO, BytesIO
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify, send_file, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename

from core.database import get_db
from core.rbac import permission_required, api_permission_required
from core.encryption import SM4Encryptor
from core.masking import DataMasker
from core.privacy import DifferentialPrivacy, PrivacyQueryEngine
from core.audit import AuditLogger, RiskLevel

data_bp = Blueprint('data', __name__)

# 延迟初始化对象
_encryptor = None
_masker = None
_audit = None

def get_encryptor():
    global _encryptor
    if _encryptor is None:
        _encryptor = SM4Encryptor()
    return _encryptor

def get_masker():
    global _masker
    if _masker is None:
        _masker = DataMasker()
    return _masker

def get_audit():
    global _audit
    if _audit is None:
        _audit = AuditLogger()
    return _audit

# 为了向后兼容，提供属性访问
encryptor = property(lambda self: get_encryptor())
masker = property(lambda self: get_masker())
audit = property(lambda self: get_audit())


# ==================== 学生数据管理 ====================

@data_bp.route('/students')
@login_required
@permission_required('data:view')
def students():
    """学生列表"""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    # 搜索条件
    search = request.args.get('search', '')
    department = request.args.get('department', '')

    conditions = []
    params = []

    if search:
        conditions.append("(student_id LIKE ? OR name LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])

    if department:
        conditions.append("department = ?")
        params.append(department)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    # 获取总数
    total = db.fetch_one(f"SELECT COUNT(*) as count FROM students WHERE {where_clause}", tuple(params))['count']

    # 获取学生列表
    query = f"""
        SELECT * FROM students
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    students_list = db.fetch_all(query, tuple(params))

    # 数据脱敏
    if not current_user.has_permission('sensitive:decrypt'):
        students_list = get_masker().mask_list(
            students_list,
            ['name', 'id_card', 'phone', 'email'],
            {'name': 'name', 'id_card': 'id_card', 'phone': 'phone', 'email': 'email'}
        )

    # 获取院系列表（用于筛选）
    departments = db.fetch_all("SELECT DISTINCT department FROM students ORDER BY department")

    return render_template('data/students.html',
                           students=students_list,
                           departments=departments,
                           page=page,
                           total=total,
                           per_page=per_page,
                           search=search,
                           department=department,
                           title='学生数据管理')


@data_bp.route('/students/create', methods=['GET', 'POST'])
@login_required
@permission_required('data:create')
def create_student():
    """创建学生记录"""
    if request.method == 'POST':
        db = get_db()

        student_id = request.form.get('student_id')
        name = request.form.get('name')
        gender = request.form.get('gender')
        birth_date = request.form.get('birth_date')
        id_card = request.form.get('id_card')
        phone = request.form.get('phone')
        email = request.form.get('email')
        department = request.form.get('department')
        major = request.form.get('major')
        class_name = request.form.get('class_name')
        enrollment_date = request.form.get('enrollment_date')
        address = request.form.get('address')
        emergency_contact = request.form.get('emergency_contact')
        emergency_phone = request.form.get('emergency_phone')

        # 加密敏感字段
        name_encrypted = get_encryptor().encrypt(name) if name else None
        id_card_encrypted = get_encryptor().encrypt(id_card) if id_card else None
        phone_encrypted = get_encryptor().encrypt(phone) if phone else None
        email_encrypted = get_encryptor().encrypt(email) if email else None
        address_encrypted = get_encryptor().encrypt(address) if address else None

        try:
            db.execute(
                """
                INSERT INTO students
                (student_id, name, name_encrypted, gender, birth_date,
                 id_card, id_card_encrypted, phone, phone_encrypted,
                 email, email_encrypted, department, major, class_name,
                 enrollment_date, address, address_encrypted,
                 emergency_contact, emergency_phone)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (student_id, name, name_encrypted, gender, birth_date,
                 id_card, id_card_encrypted, phone, phone_encrypted,
                 email, email_encrypted, department, major, class_name,
                 enrollment_date, address, address_encrypted,
                 emergency_contact, emergency_phone)
            )

            get_audit().log_data_access(
                user_id=current_user.id,
                username=current_user.username,
                data_type='student',
                data_id=db.get_connection().cursor().lastrowid,
                access_type='create',
                ip_address=request.remote_addr
            )

            flash('学生记录创建成功', 'success')
            return redirect(url_for('data.students'))

        except Exception as e:
            flash(f'创建失败: {str(e)}', 'danger')

    return render_template('data/student_form.html', title='添加学生')


@data_bp.route('/students/<int:student_id>/edit', methods=['GET', 'POST'])
@login_required
@permission_required('data:update')
def edit_student(student_id):
    """编辑学生记录"""
    db = get_db()

    student = db.fetch_one("SELECT * FROM students WHERE id = ?", (student_id,))
    if not student:
        flash('学生记录不存在', 'danger')
        return redirect(url_for('data.students'))

    if request.method == 'POST':
        # 更新字段
        update_fields = []
        params = []

        for field in ['name', 'gender', 'birth_date', 'id_card', 'phone', 'email',
                       'department', 'major', 'class_name', 'enrollment_date',
                       'address', 'emergency_contact', 'emergency_phone']:
            value = request.form.get(field)
            if value:
                update_fields.append(f"{field} = ?")
                params.append(value)

                # 加密敏感字段
                if field in ['name', 'id_card', 'phone', 'email', 'address']:
                    update_fields.append(f"{field}_encrypted = ?")
                    params.append(get_encryptor().encrypt(value))

        params.append(datetime.now())
        params.append(student_id)

        db.execute(
            f"""
            UPDATE students SET {', '.join(update_fields)}, updated_at = ?
            WHERE id = ?
            """,
            tuple(params)
        )

        get_audit().log_data_access(
            user_id=current_user.id,
            username=current_user.username,
            data_type='student',
            data_id=student_id,
            access_type='update',
            ip_address=request.remote_addr
        )

        flash('学生记录更新成功', 'success')
        return redirect(url_for('data.students'))

    return render_template('data/student_form.html', student=student, title='编辑学生')


@data_bp.route('/students/<int:student_id>/delete', methods=['POST'])
@login_required
@permission_required('data:delete')
def delete_student(student_id):
    """删除学生记录"""
    db = get_db()

    student = db.fetch_one("SELECT * FROM students WHERE id = ?", (student_id,))
    if not student:
        flash('学生记录不存在', 'danger')
        return redirect(url_for('data.students'))

    db.execute("DELETE FROM students WHERE id = ?", (student_id,))

    get_audit().log_data_access(
        user_id=current_user.id,
        username=current_user.username,
        data_type='student',
        data_id=student_id,
        access_type='delete',
        ip_address=request.remote_addr
    )

    flash('学生记录已删除', 'success')
    return redirect(url_for('data.students'))


# ==================== 教职工数据管理 ====================

@data_bp.route('/staff')
@login_required
@permission_required('data:view')
def staff():
    """教职工列表"""
    db = get_db()

    page = request.args.get('page', 1, type=int)
    per_page = 20
    offset = (page - 1) * per_page

    search = request.args.get('search', '')
    department = request.args.get('department', '')

    conditions = []
    params = []

    if search:
        conditions.append("(staff_id LIKE ? OR name LIKE ?)")
        params.extend([f'%{search}%', f'%{search}%'])

    if department:
        conditions.append("department = ?")
        params.append(department)

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    total = db.fetch_one(f"SELECT COUNT(*) as count FROM staff WHERE {where_clause}", tuple(params))['count']

    query = f"""
        SELECT id, staff_id, name, gender, department, position, title,
               hire_date, status, created_at
        FROM staff
        WHERE {where_clause}
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([per_page, offset])
    staff_list = db.fetch_all(query, tuple(params))

    departments = db.fetch_all("SELECT DISTINCT department FROM staff ORDER BY department")

    return render_template('data/staff.html',
                           staff=staff_list,
                           departments=departments,
                           page=page,
                           total=total,
                           per_page=per_page,
                           search=search,
                           department=department,
                           title='教职工数据管理')


# ==================== 差分隐私查询 ====================

@data_bp.route('/privacy-query')
@login_required
@permission_required('privacy:query')
def privacy_query():
    """差分隐私查询页面"""
    db = get_db()

    # 获取院系列表
    departments = db.fetch_all("SELECT DISTINCT department FROM students ORDER BY department")

    return render_template('data/privacy_query.html',
                           departments=departments,
                           title='差分隐私查询')


@data_bp.route('/api/privacy/query', methods=['POST'])
@login_required
def api_privacy_query():
    """执行差分隐私查询API"""
    try:
        # 手动检查权限，提供更好的错误信息
        from core.rbac import RBACManager
        rbac = RBACManager()

        if not rbac.check_permission(current_user.id, 'privacy:query'):
            return jsonify({
                'success': False,
                'error': '您没有差分隐私查询权限，请联系管理员'
            }), 403

        db = get_db()

        data = request.get_json()
        if not data:
            return jsonify({
                'success': False,
                'error': '请求数据格式错误'
            }), 400

        query_type = data.get('query_type')
        params = data.get('params', {})
        epsilon = data.get('epsilon', 1.0)

        # 初始化差分隐私引擎
        dp = DifferentialPrivacy(epsilon=epsilon, delta=1e-5)
        engine = PrivacyQueryEngine(dp)

        result = {}

        if query_type == 'count_by_department':
            department = params.get('department')
            if not department:
                # 获取第一个院系作为默认值
                dept_result = db.fetch_one("SELECT DISTINCT department FROM students LIMIT 1")
                department = dept_result['department'] if dept_result else '未知院系'
            students = db.fetch_all("SELECT * FROM students WHERE department = ?", (department,))
            true_count = len(students)
            noisy_count = dp.noisy_count(true_count)
            result = {
                'department': department,
                'true_count': true_count,
                'count': noisy_count,
                'epsilon': epsilon,
                'noise_added': noisy_count - true_count
            }

        elif query_type == 'age_distribution':
            students = db.fetch_all("SELECT birth_date FROM students WHERE birth_date IS NOT NULL")
            if not students:
                result = {'error': '没有学生数据'}
            else:
                result = engine.query_age_distribution(students)

        elif query_type == 'gender_ratio':
            students = db.fetch_all("SELECT gender FROM students")
            if not students:
                result = {'male_count': 0, 'female_count': 0, 'male_ratio': 0.5, 'female_ratio': 0.5}
            else:
                result = engine.query_gender_ratio(students)

        elif query_type == 'salary_stats':
            staff = db.fetch_all("SELECT salary FROM staff WHERE salary IS NOT NULL")
            if not staff:
                result = {'mean': 0, 'variance': 0, 'std': 0, 'min': 0, 'max': 0}
            else:
                result = engine.query_salary_statistics(staff, 0, 100000)

        elif query_type == 'department_distribution':
            students = db.fetch_all("SELECT department FROM students")
            if not students:
                result = {}
            else:
                departments = [s['department'] for s in students if s['department']]
                unique_depts = list(set(departments))
                result = dp.noisy_histogram(departments, unique_depts)

        else:
            return jsonify({
                'success': False,
                'error': f'未知的查询类型: {query_type}'
            }), 400

        # 记录查询
        get_audit().log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='privacy_query',
            resource='data',
            ip_address=request.remote_addr,
            details=json.dumps({
                'query_type': query_type,
                'params': params,
                'epsilon_used': epsilon
            })
        )

        return jsonify({
            'success': True,
            'result': result,
            'privacy_budget_used': epsilon
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@data_bp.route('/api/privacy/compare', methods=['POST'])
@login_required
def api_privacy_compare():
    """对比真实结果和差分隐私结果"""
    # 手动检查权限
    from core.rbac import RBACManager
    rbac = RBACManager()

    if not rbac.check_permission(current_user.id, 'privacy:query'):
        return jsonify({
            'success': False,
            'error': '您没有差分隐私查询权限，请联系管理员'
        }), 403

    db = get_db()

    data = request.get_json()
    if not data:
        return jsonify({
            'success': False,
            'error': '请求数据格式错误'
        }), 400

    query_type = data.get('query_type')
    epsilon = data.get('epsilon', 1.0)

    dp = DifferentialPrivacy(epsilon=epsilon)

    result = {'original': {}, 'noisy': {}, 'noise': {}}

    try:
        if query_type == 'student_count':
            # 真实计数
            true_count = db.fetch_count('students')

            # 差分隐私计数
            noisy_count = dp.noisy_count(true_count)

            result['original'] = {'count': true_count}
            result['noisy'] = {'count': noisy_count}
            result['noise'] = {
                'absolute': abs(noisy_count - true_count),
                'relative': abs(noisy_count - true_count) / true_count if true_count > 0 else 0
            }

        elif query_type == 'department_counts':
            # 各院系人数统计
            dept_counts = db.fetch_all(
                "SELECT department, COUNT(*) as count FROM students GROUP BY department"
            )

            if not dept_counts:
                result['original'] = {}
                result['noisy'] = {}
            else:
                original = {d['department']: d['count'] for d in dept_counts}
                noisy = {dept: dp.noisy_count(count) for dept, count in original.items()}

                result['original'] = original
                result['noisy'] = noisy

        else:
            return jsonify({
                'success': False,
                'error': f'未知的对比类型: {query_type}'
            }), 400

        return jsonify({
            'success': True,
            'result': result,
            'epsilon': epsilon
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


# ==================== 文件加密 ====================

@data_bp.route('/encrypt')
@login_required
@permission_required('encrypt:file')
def encrypt_page():
    """文件加密页面"""
    return render_template('data/encrypt.html', title='文件加密')


@data_bp.route('/encrypt/file', methods=['POST'])
@login_required
@permission_required('encrypt:file')
def encrypt_file():
    """加密上传的文件"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    # 保存原文件
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    original_path = os.path.join(current_app.config['UPLOAD_DIR'], f'{timestamp}_{filename}')
    file.save(original_path)

    # 加密文件
    encrypted_path = original_path + '.enc'
    success, message = get_encryptor().encrypt_file(original_path, encrypted_path)

    if success:
        # 记录到数据库
        db = get_db()
        db.execute(
            """
            INSERT INTO encrypted_files
            (user_id, original_name, stored_name, file_path, file_size, file_type)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (current_user.id, filename, os.path.basename(encrypted_path),
             encrypted_path, os.path.getsize(encrypted_path), filename.rsplit('.', 1)[-1])
        )

        get_audit().log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='file_encrypt',
            resource='file',
            resource_id=filename,
            ip_address=request.remote_addr,
            risk_level=RiskLevel.MEDIUM,
            details=f'加密文件: {filename}'
        )

        # 删除原文件
        os.remove(original_path)

        return jsonify({
            'success': True,
            'message': message,
            'encrypted_file': os.path.basename(encrypted_path)
        })

    return jsonify({'success': False, 'error': message}), 400


@data_bp.route('/decrypt/file', methods=['POST'])
@login_required
@permission_required('decrypt:file')
def decrypt_file():
    """解密文件"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': '没有选择文件'}), 400

    # 保存加密文件
    filename = secure_filename(file.filename)
    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    encrypted_path = os.path.join(current_app.config['UPLOAD_DIR'], f'{timestamp}_{filename}')
    file.save(encrypted_path)

    # 解密文件
    decrypted_path = encrypted_path.replace('.enc', '')
    success, message = get_encryptor().decrypt_file(encrypted_path, decrypted_path)

    if success:
        get_audit().log_action(
            user_id=current_user.id,
            username=current_user.username,
            action='file_decrypt',
            resource='file',
            resource_id=filename,
            ip_address=request.remote_addr,
            risk_level=RiskLevel.HIGH,
            details=f'解密文件: {filename}'
        )

        # 清理临时文件
        os.remove(encrypted_path)

        # 返回解密后的文件
        return send_file(
            decrypted_path,
            as_attachment=True,
            download_name=filename.replace('.enc', '')
        )

    return jsonify({'success': False, 'error': message}), 400


# ==================== 数据导出 ====================

@data_bp.route('/export/students')
@login_required
@permission_required('data:export')
def export_students():
    """导出学生数据"""
    db = get_db()

    students = db.fetch_all("SELECT * FROM students")

    # 创建CSV
    output = StringIO()
    writer = csv.writer(output)

    # 写入表头
    writer.writerow(['学号', '姓名', '性别', '出生日期', '院系', '专业', '班级', '入学日期'])

    # 写入数据
    for student in students:
        # 脱敏处理
        name = get_masker().mask_name(student['name']) if student['name'] else ''
        writer.writerow([
            student['student_id'],
            name,
            student['gender'],
            student['birth_date'],
            student['department'],
            student['major'],
            student['class_name'],
            student['enrollment_date']
        ])

    output.seek(0)

    get_audit().log_action(
        user_id=current_user.id,
        username=current_user.username,
        action='export_data',
        resource='student',
        ip_address=request.remote_addr,
        risk_level=RiskLevel.MEDIUM,
        details=f'导出学生数据: {len(students)}条记录'
    )

    return send_file(
        BytesIO(output.getvalue().encode('utf-8-sig')),
        as_attachment=True,
        download_name=f'students_{datetime.now().strftime("%Y%m%d")}.csv',
        mimetype='text/csv'
    )