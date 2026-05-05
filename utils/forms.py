#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
表单模块
定义WTForms表单类
"""

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, TextAreaField, DateField
from wtforms.validators import DataRequired, Email, Length, EqualTo, Optional, ValidationError
import re


class LoginForm(FlaskForm):
    """登录表单"""
    username = StringField('用户名', validators=[
        DataRequired(message='请输入用户名'),
        Length(1, 50, message='用户名长度为1-50个字符')
    ])
    password = PasswordField('密码', validators=[
        DataRequired(message='请输入密码'),
        Length(1, 128, message='密码长度不超过128个字符')
    ])
    remember = BooleanField('记住我')


class ChangePasswordForm(FlaskForm):
    """修改密码表单"""
    old_password = PasswordField('原密码', validators=[
        DataRequired(message='请输入原密码')
    ])
    new_password = PasswordField('新密码', validators=[
        DataRequired(message='请输入新密码'),
        Length(8, 128, message='密码长度为8-128个字符')
    ])
    confirm_password = PasswordField('确认密码', validators=[
        DataRequired(message='请确认新密码'),
        EqualTo('new_password', message='两次输入的密码不一致')
    ])

    def validate_new_password(self, field):
        """验证密码强度"""
        password = field.data

        if not re.search(r'[A-Z]', password):
            raise ValidationError('密码需要包含至少一个大写字母')
        if not re.search(r'[a-z]', password):
            raise ValidationError('密码需要包含至少一个小写字母')
        if not re.search(r'\d', password):
            raise ValidationError('密码需要包含至少一个数字')
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            raise ValidationError('密码需要包含至少一个特殊字符')


class UserForm(FlaskForm):
    """用户表单"""
    username = StringField('用户名', validators=[
        DataRequired(message='请输入用户名'),
        Length(1, 50, message='用户名长度为1-50个字符')
    ])
    real_name = StringField('真实姓名', validators=[
        Optional(),
        Length(0, 50, message='姓名长度不超过50个字符')
    ])
    email = StringField('邮箱', validators=[
        Optional(),
        Email(message='请输入有效的邮箱地址')
    ])
    phone = StringField('电话', validators=[
        Optional(),
        Length(0, 20, message='电话长度不超过20个字符')
    ])
    role_id = SelectField('角色', coerce=int, validators=[
        DataRequired(message='请选择角色')
    ])
    department = StringField('部门', validators=[
        Optional(),
        Length(0, 100, message='部门长度不超过100个字符')
    ])
    position = StringField('职位', validators=[
        Optional(),
        Length(0, 50, message='职位长度不超过50个字符')
    ])
    status = SelectField('状态', coerce=int, choices=[
        (1, '启用'),
        (0, '禁用')
    ])


class StudentForm(FlaskForm):
    """学生表单"""
    student_id = StringField('学号', validators=[
        DataRequired(message='请输入学号'),
        Length(1, 20, message='学号长度为1-20个字符')
    ])
    name = StringField('姓名', validators=[
        DataRequired(message='请输入姓名'),
        Length(1, 50, message='姓名长度为1-50个字符')
    ])
    gender = SelectField('性别', choices=[
        ('', '请选择'),
        ('男', '男'),
        ('女', '女')
    ])
    birth_date = DateField('出生日期', validators=[Optional()])
    id_card = StringField('身份证号', validators=[
        Optional(),
        Length(15, 18, message='身份证号长度为15或18个字符')
    ])
    phone = StringField('联系电话', validators=[
        Optional(),
        Length(11, 11, message='请输入11位手机号')
    ])
    email = StringField('邮箱', validators=[
        Optional(),
        Email(message='请输入有效的邮箱地址')
    ])
    department = StringField('院系', validators=[
        Optional(),
        Length(0, 100, message='院系长度不超过100个字符')
    ])
    major = StringField('专业', validators=[
        Optional(),
        Length(0, 100, message='专业长度不超过100个字符')
    ])
    class_name = StringField('班级', validators=[
        Optional(),
        Length(0, 50, message='班级长度不超过50个字符')
    ])
    enrollment_date = DateField('入学日期', validators=[Optional()])
    address = TextAreaField('家庭住址', validators=[
        Optional(),
        Length(0, 200, message='地址长度不超过200个字符')
    ])
    emergency_contact = StringField('紧急联系人', validators=[Optional()])
    emergency_phone = StringField('紧急联系电话', validators=[Optional()])

    def validate_id_card(self, field):
        """验证身份证号格式"""
        if field.data:
            id_card = field.data
            if len(id_card) == 18:
                if not re.match(r'^\d{17}[\dX]$', id_card):
                    raise ValidationError('身份证号格式不正确')
            elif len(id_card) == 15:
                if not re.match(r'^\d{15}$', id_card):
                    raise ValidationError('身份证号格式不正确')

    def validate_phone(self, field):
        """验证手机号格式"""
        if field.data:
            if not re.match(r'^1[3-9]\d{9}$', field.data):
                raise ValidationError('请输入有效的手机号')


class SearchForm(FlaskForm):
    """搜索表单"""
    keyword = StringField('关键词', validators=[
        DataRequired(message='请输入搜索关键词'),
        Length(1, 100, message='关键词长度为1-100个字符')
    ])