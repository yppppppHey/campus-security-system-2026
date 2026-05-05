#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
辅助函数模块
提供各种辅助功能
"""

import random
import string
import csv
import io
import re
from datetime import datetime, date
from typing import Any, Dict, List


def generate_test_data():
    """生成测试数据"""
    from core.database import get_db
    from core.encryption import SM4Encryptor

    db = get_db()
    encryptor = SM4Encryptor()

    # 检查是否已有数据
    if db.fetch_count('students') > 0:
        print("测试数据已存在，跳过生成")
        return

    print("开始生成测试数据...")

    # 院系列表
    departments = [
        '计算机科学与技术学院', '软件学院', '信息工程学院',
        '数学与统计学院', '物理学院', '化学与化工学院',
        '经济管理学院', '外国语学院', '文学院', '法学院'
    ]

    # 专业列表
    majors = {
        '计算机科学与技术学院': ['计算机科学与技术', '网络工程', '信息安全'],
        '软件学院': ['软件工程', '数字媒体技术'],
        '信息工程学院': ['电子信息工程', '通信工程', '物联网工程'],
        '数学与统计学院': ['数学与应用数学', '统计学', '信息与计算科学'],
        '物理学院': ['物理学', '应用物理学'],
        '化学与化工学院': ['化学', '应用化学', '化学工程与工艺'],
        '经济管理学院': ['工商管理', '会计学', '金融学', '国际经济与贸易'],
        '外国语学院': ['英语', '日语', '翻译'],
        '文学院': ['汉语言文学', '历史学', '哲学'],
        '法学院': ['法学', '知识产权']
    }

    # 姓氏列表
    surnames = ['张', '王', '李', '赵', '刘', '陈', '杨', '黄', '周', '吴',
                '徐', '孙', '马', '朱', '胡', '郭', '何', '林', '罗', '高']

    # 名字列表
    given_names = ['伟', '芳', '娜', '秀英', '敏', '静', '丽', '强', '磊', '军',
                   '洋', '勇', '艳', '杰', '娟', '涛', '明', '超', '秀兰', '霞',
                   '平', '刚', '桂英', '文', '华', '建国', '建军', '浩', '宇', '轩']

    # 生成学生数据
    students = []
    used_ids = set()

    for i in range(200):
        dept = random.choice(departments)
        major = random.choice(majors[dept])
        year = random.randint(2020, 2023)

        # 生成唯一的学生ID
        while True:
            student_id = f"{year}{random.randint(1000, 9999)}"
            if student_id not in used_ids:
                used_ids.add(student_id)
                break

        name = random.choice(surnames) + ''.join(random.sample(given_names, random.randint(1, 2)))
        gender = random.choice(['男', '女'])
        birth_year = random.randint(1998, 2005)
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)
        birth_date = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"

        # 生成身份证号
        area_code = random.choice(['320102', '320104', '320106', '320111', '320113'])
        id_card = f"{area_code}{birth_year}{birth_month:02d}{birth_day:02d}{random.randint(100, 999)}{random.choice(['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'X'])}"

        # 生成手机号
        phone = f"1{random.choice(['38', '39', '58', '59', '86', '87', '36', '37'])}{random.randint(10000000, 99999999)}"

        # 生成邮箱
        email_domains = ['qq.com', '163.com', 'gmail.com', 'outlook.com', 'campus.edu.cn']
        email = f"student{student_id}@{random.choice(email_domains)}"

        students.append({
            'student_id': student_id,
            'name': name,
            'name_encrypted': encryptor.encrypt(name),
            'gender': gender,
            'birth_date': birth_date,
            'id_card': id_card,
            'id_card_encrypted': encryptor.encrypt(id_card),
            'phone': phone,
            'phone_encrypted': encryptor.encrypt(phone),
            'email': email,
            'email_encrypted': encryptor.encrypt(email),
            'department': dept,
            'major': major,
            'class_name': f"{year}级{major}1班",
            'enrollment_date': f"{year}-09-01",
            'address': f"江苏省南京市{random.choice(['玄武区', '秦淮区', '建邺区', '鼓楼区', '栖霞区'])}{random.randint(1, 100)}号",
            'emergency_contact': random.choice(surnames) + random.choice(given_names),
            'emergency_phone': f"1{random.choice(['38', '39', '58'])}{random.randint(10000000, 99999999)}"
        })

    # 批量插入学生数据
    for student in students:
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
            (
                student['student_id'], student['name'], student['name_encrypted'],
                student['gender'], student['birth_date'],
                student['id_card'], student['id_card_encrypted'],
                student['phone'], student['phone_encrypted'],
                student['email'], student['email_encrypted'],
                student['department'], student['major'], student['class_name'],
                student['enrollment_date'], student['address'],
                encryptor.encrypt(student['address']),
                student['emergency_contact'], student['emergency_phone']
            )
        )

    print(f"已生成 {len(students)} 条学生数据")

    # 生成教职工数据
    staff_list = []
    positions = ['讲师', '副教授', '教授', '助教', '实验师', '高级实验师']
    titles = ['初级', '中级', '副高级', '正高级']

    for i in range(50):
        dept = random.choice(departments)
        staff_id = f"T{random.randint(10000, 99999)}"
        name = random.choice(surnames) + ''.join(random.sample(given_names, random.randint(1, 2)))
        gender = random.choice(['男', '女'])
        birth_year = random.randint(1965, 1995)
        birth_month = random.randint(1, 12)
        birth_day = random.randint(1, 28)
        birth_date = f"{birth_year}-{birth_month:02d}-{birth_day:02d}"

        salary = random.randint(8000, 30000)

        staff_list.append({
            'staff_id': staff_id,
            'name': name,
            'name_encrypted': encryptor.encrypt(name),
            'gender': gender,
            'birth_date': birth_date,
            'department': dept,
            'position': random.choice(positions),
            'title': random.choice(titles),
            'hire_date': f"{random.randint(2000, 2023)}-{random.randint(1, 12):02d}-01",
            'salary': salary,
            'salary_encrypted': encryptor.encrypt(str(salary))
        })

    for staff in staff_list:
        db.execute(
            """
            INSERT INTO staff
            (staff_id, name, name_encrypted, gender, birth_date,
             department, position, title, hire_date, salary, salary_encrypted, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (
                staff['staff_id'], staff['name'], staff['name_encrypted'],
                staff['gender'], staff['birth_date'],
                staff['department'], staff['position'], staff['title'],
                staff['hire_date'], staff['salary'], staff['salary_encrypted']
            )
        )

    print(f"已生成 {len(staff_list)} 条教职工数据")
    print("测试数据生成完成！")


def format_datetime(value: datetime, format: str = '%Y-%m-%d %H:%M:%S') -> str:
    """格式化日期时间"""
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    return value.strftime(format)


def format_date(value: date, format: str = '%Y-%m-%d') -> str:
    """格式化日期"""
    if value is None:
        return ''
    if isinstance(value, str):
        return value
    return value.strftime(format)


def generate_random_string(length: int = 16) -> str:
    """生成随机字符串"""
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def validate_id_card(id_card: str) -> bool:
    """验证身份证号格式"""
    if not id_card:
        return False

    if len(id_card) == 18:
        if not id_card[:-1].isdigit():
            return False
        if id_card[-1] not in '0123456789X':
            return False

        weights = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2]
        check_codes = '10X98765432'

        total = sum(int(id_card[i]) * weights[i] for i in range(17))
        if check_codes[total % 11] != id_card[-1]:
            return False

        return True

    elif len(id_card) == 15:
        return id_card.isdigit()

    return False


def validate_phone(phone: str) -> bool:
    """验证手机号格式"""
    if not phone or len(phone) != 11:
        return False
    return phone.startswith('1') and phone.isdigit()


def validate_email(email: str) -> bool:
    """验证邮箱格式"""
    if not email:
        return False
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def get_client_ip(request) -> str:
    """获取客户端IP地址"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or '0.0.0.0'


def paginate(data: List, page: int, per_page: int) -> Dict:
    """分页处理"""
    total = len(data)
    start = (page - 1) * per_page
    end = start + per_page

    return {
        'items': data[start:end],
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    }