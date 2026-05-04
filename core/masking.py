#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
数据脱敏模块
实现敏感数据的动态脱敏处理

功能:
    - 身份证号脱敏
    - 手机号脱敏
    - 邮箱脱敏
    - 银行卡脱敏
    - 姓名/地址脱敏
    - 自定义脱敏规则
"""

import re
import random
import string
from typing import Union, List, Dict, Any, Callable, Optional,Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class MaskingStrategy(Enum):
    """脱敏策略枚举"""
    FULL = 'full'           # 完全隐藏
    PARTIAL = 'partial'     # 部分隐藏
    RANDOM = 'random'       # 随机替换
    HASH = 'hash'           # 哈希替换
    TRUNCATE = 'truncate'   # 截断
    NULL = 'null'           # 空值替换


class DataMasker:
    """
    数据脱敏器
    提供多种数据类型的脱敏方法
    """

    # 默认脱敏字符
    MASK_CHAR = '*'

    # 预定义的脱敏规则
    RULES = {
        'id_card': {
            'pattern': r'^(\d{6})(\d{4})(\d{2})(\d{2})(\d{3})([\dX])$',
            'strategy': MaskingStrategy.PARTIAL,
            'keep_prefix': 6,
            'keep_suffix': 4,
            'description': '身份证号脱敏'
        },
        'phone': {
            'pattern': r'^(\d{3})(\d{4})(\d{4})$',
            'strategy': MaskingStrategy.PARTIAL,
            'keep_prefix': 3,
            'keep_suffix': 4,
            'description': '手机号脱敏'
        },
        'email': {
            'pattern': r'^([^@]{1,3})[^@]*(@[^.]+\.[^.]+)$',
            'strategy': MaskingStrategy.PARTIAL,
            'keep_prefix': 3,
            'keep_suffix': 'domain',
            'description': '邮箱脱敏'
        },
        'bank_card': {
            'pattern': r'^(\d{4})\d+(\d{4})$',
            'strategy': MaskingStrategy.PARTIAL,
            'keep_prefix': 4,
            'keep_suffix': 4,
            'description': '银行卡号脱敏'
        },
        'name': {
            'strategy': MaskingStrategy.PARTIAL,
            'keep_first': 1,
            'description': '姓名脱敏'
        },
        'address': {
            'strategy': MaskingStrategy.PARTIAL,
            'keep_prefix': 6,
            'description': '地址脱敏'
        },
        'password': {
            'strategy': MaskingStrategy.FULL,
            'description': '密码脱敏'
        },
        'salary': {
            'strategy': MaskingStrategy.RANDOM,
            'range': (0.8, 1.2),
            'description': '薪资脱敏'
        }
    }

    def __init__(self, custom_rules: Dict[str, Dict] = None):
        """
        初始化数据脱敏器

        Args:
            custom_rules: 自定义脱敏规则
        """
        self.rules = self.RULES.copy()
        if custom_rules:
            self.rules.update(custom_rules)

        # 注册内置脱敏方法
        self._maskers = {
            MaskingStrategy.FULL: self._mask_full,
            MaskingStrategy.PARTIAL: self._mask_partial,
            MaskingStrategy.RANDOM: self._mask_random,
            MaskingStrategy.HASH: self._mask_hash,
            MaskingStrategy.TRUNCATE: self._mask_truncate,
            MaskingStrategy.NULL: self._mask_null
        }

        logger.info("数据脱敏器初始化完成")

    def mask(self, data: str, data_type: str) -> str:
        """
        根据数据类型进行脱敏

        Args:
            data: 原始数据
            data_type: 数据类型

        Returns:
            str: 脱敏后的数据
        """
        if not data:
            return data

        rule = self.rules.get(data_type)
        if not rule:
            logger.warning(f"未知的脱敏类型: {data_type}")
            return data

        strategy = rule.get('strategy', MaskingStrategy.PARTIAL)
        masker = self._maskers.get(strategy)

        if not masker:
            return data

        return masker(data, rule)

    def mask_id_card(self, id_card: str) -> str:
        """
        身份证号脱敏
        保留前6位（地区码）和后4位，中间用*替代

        Args:
            id_card: 身份证号

        Returns:
            str: 脱敏后的身份证号
        """
        if not id_card or len(id_card) < 10:
            return id_card

        # 15位或18位身份证
        if len(id_card) == 15:
            return id_card[:6] + '******' + id_card[-3:]
        elif len(id_card) == 18:
            return id_card[:6] + '********' + id_card[-4:]
        else:
            return self._mask_partial(id_card, {'keep_prefix': 6, 'keep_suffix': 4})

    def mask_phone(self, phone: str) -> str:
        """
        手机号脱敏
        保留前3位和后4位，中间用*替代

        Args:
            phone: 手机号

        Returns:
            str: 脱敏后的手机号
        """
        if not phone or len(phone) < 7:
            return phone

        # 处理不同格式的手机号
        phone = phone.replace('-', '').replace(' ', '')

        if len(phone) == 11:
            return phone[:3] + '****' + phone[-4:]
        else:
            return self._mask_partial(phone, {'keep_prefix': 3, 'keep_suffix': 4})

    def mask_email(self, email: str) -> str:
        """
        邮箱脱敏
        保留前3个字符和域名部分

        Args:
            email: 邮箱地址

        Returns:
            str: 脱敏后的邮箱
        """
        if not email or '@' not in email:
            return email

        parts = email.split('@')
        username = parts[0]
        domain = parts[1]

        if len(username) <= 3:
            masked_username = username + '***'
        else:
            masked_username = username[:3] + '***'

        return masked_username + '@' + domain

    def mask_bank_card(self, card_no: str) -> str:
        """
        银行卡号脱敏
        保留前4位和后4位

        Args:
            card_no: 银行卡号

        Returns:
            str: 脱敏后的银行卡号
        """
        if not card_no or len(card_no) < 8:
            return card_no

        card_no = card_no.replace(' ', '').replace('-', '')

        return card_no[:4] + '****' + card_no[-4:]

    def mask_name(self, name: str) -> str:
        """
        姓名脱敏
        保留姓氏，其余用*替代

        Args:
            name: 姓名

        Returns:
            str: 脱敏后的姓名
        """
        if not name:
            return name

        if len(name) == 1:
            return name
        elif len(name) == 2:
            return name[0] + '*'
        else:
            return name[0] + '*' * (len(name) - 1)

    def mask_address(self, address: str, keep_length: int = 6) -> str:
        """
        地址脱敏
        保留前几个字符

        Args:
            address: 地址
            keep_length: 保留的字符数

        Returns:
            str: 脱敏后的地址
        """
        if not address:
            return address

        if len(address) <= keep_length:
            return address + '***'

        return address[:keep_length] + '***' + '*' * (len(address) - keep_length - 3)

    def mask_password(self, password: str) -> str:
        """
        密码完全脱敏

        Args:
            password: 密码

        Returns:
            str: 脱敏后的密码（固定显示）
        """
        return '******'

    def mask_salary(self, salary: Union[int, float],
                    range_ratio: Tuple[float, float] = (0.8, 1.2)) -> float:
        """
        薪资脱敏（随机扰动）

        Args:
            salary: 薪资
            range_ratio: 扰动范围比例

        Returns:
            float: 脱敏后的薪资
        """
        if not salary:
            return 0.0

        ratio = random.uniform(range_ratio[0], range_ratio[1])
        return round(salary * ratio, 2)

    def mask_ip_address(self, ip: str) -> str:
        """
        IP地址脱敏
        保留前两段

        Args:
            ip: IP地址

        Returns:
            str: 脱敏后的IP地址
        """
        if not ip:
            return ip

        parts = ip.split('.')
        if len(parts) == 4:
            return parts[0] + '.' + parts[1] + '.***.***'
        return ip

    def mask_date(self, date_str: str) -> str:
        """
        日期脱敏
        只保留年份

        Args:
            date_str: 日期字符串

        Returns:
            str: 脱敏后的日期
        """
        if not date_str:
            return date_str

        # 提取年份
        year_match = re.match(r'^(\d{4})', date_str)
        if year_match:
            return year_match.group(1) + '-**-**'
        return date_str

    def _mask_full(self, data: str, rule: Dict) -> str:
        """完全隐藏"""
        return self.MASK_CHAR * min(len(data), 8)

    def _mask_partial(self, data: str, rule: Dict) -> str:
        """部分隐藏"""
        keep_prefix = rule.get('keep_prefix', 0)
        keep_suffix = rule.get('keep_suffix', 0)
        keep_first = rule.get('keep_first', 0)

        # 确保 keep_prefix 和 keep_suffix 是整数
        if not isinstance(keep_prefix, int):
            keep_prefix = 0
        if not isinstance(keep_suffix, int):
            keep_suffix = 0

        if keep_first:
            # 保留第一个字符
            if len(data) <= keep_first:
                return data
            return data[:keep_first] + self.MASK_CHAR * (len(data) - keep_first)

        if keep_prefix + keep_suffix >= len(data):
            return data

        masked_length = len(data) - keep_prefix - keep_suffix
        return data[:keep_prefix] + self.MASK_CHAR * masked_length + data[-keep_suffix:]

    def _mask_random(self, data: str, rule: Dict) -> str:
        """随机替换"""
        if isinstance(data, (int, float)):
            range_ratio = rule.get('range', (0.8, 1.2))
            ratio = random.uniform(range_ratio[0], range_ratio[1])
            return str(round(float(data) * ratio, 2))

        # 字符串随机替换
        length = len(data)
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

    def _mask_hash(self, data: str, rule: Dict) -> str:
        """哈希替换"""
        import hashlib
        hash_value = hashlib.md5(data.encode()).hexdigest()[:8]
        return f"HASH_{hash_value}"

    def _mask_truncate(self, data: str, rule: Dict) -> str:
        """截断"""
        length = rule.get('truncate_length', 10)
        if len(data) <= length:
            return data
        return data[:length] + '...'

    def _mask_null(self, data: str, rule: Dict) -> str:
        """空值替换"""
        return ''

    def mask_dict(self, data: Dict, fields: List[str],
                  field_types: Dict[str, str] = None) -> Dict:
        """
        对字典中的指定字段进行脱敏

        Args:
            data: 数据字典
            fields: 需要脱敏的字段列表
            field_types: 字段类型映射

        Returns:
            Dict: 脱敏后的数据
        """
        result = data.copy()
        field_types = field_types or {}

        for field in fields:
            if field in result and result[field]:
                field_type = field_types.get(field, field)
                result[field] = self.mask(str(result[field]), field_type)

        return result

    def mask_list(self, data: List[Dict], fields: List[str],
                  field_types: Dict[str, str] = None) -> List[Dict]:
        """
        对列表中的数据进行批量脱敏

        Args:
            data: 数据列表
            fields: 需要脱敏的字段列表
            field_types: 字段类型映射

        Returns:
            List[Dict]: 脱敏后的数据列表
        """
        return [self.mask_dict(item, fields, field_types) for item in data]

    def add_custom_rule(self, name: str, rule: Dict):
        """
        添加自定义脱敏规则

        Args:
            name: 规则名称
            rule: 规则配置
        """
        self.rules[name] = rule
        logger.info(f"添加自定义脱敏规则: {name}")

    def get_available_rules(self) -> Dict[str, Dict]:
        """获取所有可用的脱敏规则"""
        return self.rules.copy()


class MaskingPolicy:
    """
    脱敏策略管理器
    根据用户角色和数据敏感级别决定脱敏策略
    """

    # 敏感级别定义
    SENSITIVITY_LEVELS = {
        1: '低敏感',     # 公开信息
        2: '中敏感',     # 内部信息
        3: '高敏感',     # 重要信息
        4: '极敏感'      # 核心机密
    }

    # 角色与可查看敏感级别的映射
    ROLE_SENSITIVITY = {
        'admin': 4,      # 管理员可查看所有
        'security': 3,   # 安全员可查看高敏感
        'auditor': 2,    # 审计员可查看中敏感
        'user': 1,       # 普通用户只能查看低敏感
        'guest': 0       # 访客不能查看敏感数据
    }

    def __init__(self, masker: DataMasker):
        """
        初始化脱敏策略管理器

        Args:
            masker: 数据脱敏器实例
        """
        self.masker = masker

    def should_mask(self, role: str, sensitivity_level: int) -> bool:
        """
        判断是否需要脱敏

        Args:
            role: 用户角色
            sensitivity_level: 数据敏感级别

        Returns:
            bool: 是否需要脱敏
        """
        allowed_level = self.ROLE_SENSITIVITY.get(role, 0)
        return sensitivity_level > allowed_level

    def apply_policy(self, data: Dict, user_role: str,
                     field_policies: Dict[str, int]) -> Dict:
        """
        应用脱敏策略

        Args:
            data: 数据字典
            user_role: 用户角色
            field_policies: 字段敏感级别映射

        Returns:
            Dict: 应用策略后的数据
        """
        result = data.copy()

        for field, level in field_policies.items():
            if field in result and self.should_mask(user_role, level):
                result[field] = self.masker.mask(str(result[field]), field)

        return result

    def get_masked_fields(self, user_role: str,
                          field_policies: Dict[str, int]) -> List[str]:
        """
        获取需要脱敏的字段列表

        Args:
            user_role: 用户角色
            field_policies: 字段敏感级别映射

        Returns:
            List[str]: 需要脱敏的字段列表
        """
        masked_fields = []
        for field, level in field_policies.items():
            if self.should_mask(user_role, level):
                masked_fields.append(field)
        return masked_fields


class DynamicMasker:
    """
    动态脱敏器
    实现基于查询上下文的动态脱敏
    """

    def __init__(self, masker: DataMasker, policy: MaskingPolicy):
        """
        初始化动态脱敏器

        Args:
            masker: 数据脱敏器
            policy: 脱敏策略
        """
        self.masker = masker
        self.policy = policy

    def mask_query_result(self, result: List[Dict], user_role: str,
                          schema: Dict[str, Dict]) -> List[Dict]:
        """
        对查询结果进行动态脱敏

        Args:
            result: 查询结果列表
            user_role: 用户角色
            schema: 数据模式（包含字段敏感级别）

        Returns:
            List[Dict]: 脱敏后的结果
        """
        # 构建字段敏感级别映射
        field_policies = {
            field: info.get('sensitivity', 1)
            for field, info in schema.items()
        }

        # 获取需要脱敏的字段
        masked_fields = self.policy.get_masked_fields(user_role, field_policies)

        if not masked_fields:
            return result

        # 执行脱敏
        return self.masker.mask_list(result, masked_fields)

    def mask_single_record(self, record: Dict, user_role: str,
                           schema: Dict[str, Dict]) -> Dict:
        """
        对单条记录进行动态脱敏

        Args:
            record: 数据记录
            user_role: 用户角色
            schema: 数据模式

        Returns:
            Dict: 脱敏后的记录
        """
        field_policies = {
            field: info.get('sensitivity', 1)
            for field, info in schema.items()
        }

        return self.policy.apply_policy(record, user_role, field_policies)


if __name__ == '__main__':
    # 测试数据脱敏
    print("=" * 60)
    print("数据脱敏模块测试")
    print("=" * 60)

    masker = DataMasker()

    # 测试身份证脱敏
    print("\n1. 身份证号脱敏")
    id_cards = ['320102199001011234', '32010219900101123X', '320102900101123']
    for id_card in id_cards:
        masked = masker.mask_id_card(id_card)
        print(f"  原始: {id_card}")
        print(f"  脱敏: {masked}")

    # 测试手机号脱敏
    print("\n2. 手机号脱敏")
    phones = ['13812345678', '138-1234-5678', '138 1234 5678']
    for phone in phones:
        masked = masker.mask_phone(phone)
        print(f"  原始: {phone}")
        print(f"  脱敏: {masked}")

    # 测试邮箱脱敏
    print("\n3. 邮箱脱敏")
    emails = ['test@example.com', 'admin@campus.edu.cn', 'a@b.com']
    for email in emails:
        masked = masker.mask_email(email)
        print(f"  原始: {email}")
        print(f"  脱敏: {masked}")

    # 测试姓名脱敏
    print("\n4. 姓名脱敏")
    names = ['张三', '李四四', '王五六六', '赵']
    for name in names:
        masked = masker.mask_name(name)
        print(f"  原始: {name}")
        print(f"  脱敏: {masked}")

    # 测试银行卡脱敏
    print("\n5. 银行卡号脱敏")
    cards = ['6222021234567890123', '6222 0212 3456 7890 123']
    for card in cards:
        masked = masker.mask_bank_card(card)
        print(f"  原始: {card}")
        print(f"  脱敏: {masked}")

    # 测试地址脱敏
    print("\n6. 地址脱敏")
    addresses = ['江苏省南京市玄武区北京东路1号', '北京市海淀区']
    for addr in addresses:
        masked = masker.mask_address(addr)
        print(f"  原始: {addr}")
        print(f"  脱敏: {masked}")

    # 测试字典脱敏
    print("\n7. 字典数据脱敏")
    user_data = {
        'name': '张三',
        'id_card': '320102199001011234',
        'phone': '13812345678',
        'email': 'zhangsan@example.com',
        'address': '江苏省南京市玄武区',
        'salary': 8000
    }
    masked_data = masker.mask_dict(user_data, ['name', 'id_card', 'phone', 'email', 'salary'])
    print(f"  原始数据: {user_data}")
    print(f"  脱敏数据: {masked_data}")

    # 测试脱敏策略
    print("\n8. 脱敏策略测试")
    policy = MaskingPolicy(masker)

    test_data = {'name': '张三', 'id_card': '320102199001011234', 'phone': '13812345678'}
    field_policies = {'name': 2, 'id_card': 4, 'phone': 3}

    for role in ['admin', 'security', 'auditor', 'user', 'guest']:
        result = policy.apply_policy(test_data, role, field_policies)
        print(f"  角色 {role}: {result}")

    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)