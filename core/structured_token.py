#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
结构化加密格式（Structured Encryption Format, SEF）引擎
创新点：SM4+脱敏联合加密模式 — 密文内嵌脱敏

SEF格式将敏感字段存储为单一结构化密文字符串，内部包含：
- 可见前缀/后缀：无需解密即可展示（脱敏形态）
- 加密核心：SM4加密的中间部分，需授权才能解密
- HMAC令牌：确定性哈希，支持密文上等值查询
- 类型标签：标识数据类型，驱动脱敏策略

格式: SEF:v1:{type}:{visible_prefix}:{visible_suffix}:{hmac_token}:{encrypted_core}
"""

import hmac
import hashlib
import secrets
import logging
from typing import Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# SEF类型配置 — 定义每种数据类型的可见部分和脱敏模式
SEF_TYPE_CONFIG = {
    'id_card': {
        'visible_prefix': 6,
        'visible_suffix': 4,
        'mask_pattern': '{prefix}{stars}{suffix}',
        'star_count': 8,
        'description': '身份证号',
        'example': '320102199001011234 -> 320102********1234',
        'min_length': 10,  # 最小有效长度
    },
    'phone': {
        'visible_prefix': 3,
        'visible_suffix': 4,
        'mask_pattern': '{prefix}{stars}{suffix}',
        'star_count': 4,
        'description': '手机号',
        'example': '13812345678 -> 138****5678',
        'min_length': 7,
    },
    'email': {
        'visible_prefix': 3,
        'visible_suffix': 0,
        'mask_pattern': '{prefix}{stars}@{domain}',
        'star_count': 6,
        'description': '邮箱',
        'example': 'zhangsan@example.com -> zha******@example.com',
        'min_length': 5,
        # 邮箱特殊处理：域名部分可见，不加密
        'preserve_domain': True,
    },
    'name': {
        'visible_prefix': 1,
        'visible_suffix': 0,
        'mask_pattern': '{prefix}{stars}',
        'star_count': 1,
        'description': '姓名',
        'example': '张三 -> 张*',
        'min_length': 1,
    },
    'address': {
        'visible_prefix': 6,
        'visible_suffix': 0,
        'mask_pattern': '{prefix}{stars}',
        'star_count': 4,
        'description': '地址',
        'example': '江苏省南京市鼓楼区 -> 江苏省南京市...',
        'min_length': 1,
    },
    'salary': {
        'visible_prefix': 0,
        'visible_suffix': 0,
        'mask_pattern': '******',
        'star_count': 6,
        'description': '薪资',
        'example': '15000 -> ******',
        'min_length': 1,
    },
    'bank_card': {
        'visible_prefix': 4,
        'visible_suffix': 4,
        'mask_pattern': '{prefix}{stars}{suffix}',
        'star_count': 8,
        'description': '银行卡号',
        'example': '6222021234567890123 -> 6222*********0123',
        'min_length': 8,
    },
}

SEF_VERSION = 'v1'
SEF_PREFIX = 'SEF'
SEF_DELIMITER = ':'
HMAC_LENGTH = 12  # HMAC token截取长度（十六进制字符数）


class StructuredToken:
    """
    结构化加密令牌 — SM4+脱敏联合加密格式核心引擎

    创新点：
    1. 加密即脱敏 — 密文格式本身决定了可见范围，无需额外脱敏处理
    2. 零解密脱敏 — 从密文直接提取可见部分生成脱敏文本
    3. 密文查询 — HMAC令牌支持在密文上做等值查询
    4. 类型感知 — 不同数据类型有不同的可见规则和脱敏模式

    使用示例:
        token = StructuredToken(sm4_encryptor)

        # 编码：明文 -> SEF密文
        sef = token.encode('320102199001011234', 'id_card')
        # -> 'SEF:v1:id_card:320102:1234:a3f8c2d1e5b6:Q2J...'

        # 零解密脱敏：直接从SEF生成脱敏文本
        display = token.to_display(sef)
        # -> '320102********1234'

        # 完全解密：需要授权
        plaintext = token.decode_full(sef)
        # -> '320102199001011234'

        # 密文查询：计算搜索令牌
        search_token = token.compute_search_token('320102199001011234')
        # -> 'a3f8c2d1e5b6' (与SEF中的hmac_token一致)
    """

    def __init__(self, sm4_encryptor, hmac_key: bytes = None):
        """
        初始化结构化令牌引擎

        Args:
            sm4_encryptor: SM4Encryptor实例，用于加密/解密核心数据
            hmac_key: HMAC密钥，如果为None则从加密密钥派生
        """
        self.encryptor = sm4_encryptor
        # 使用独立的HMAC密钥派生，而非直接使用加密密钥
        if hmac_key is None:
            # 从SM4密钥派生HMAC密钥（使用HKDF-like方法）
            self.hmac_key = hashlib.sha256(
                b'SEF_HMAC_KEY_DERIVE' + sm4_encryptor.key
            ).digest()
        else:
            self.hmac_key = hmac_key

    def _validate_input(self, plaintext: str, data_type: str) -> Tuple[bool, str]:
        """
        验证输入数据

        Args:
            plaintext: 原始明文
            data_type: 数据类型

        Returns:
            Tuple[bool, str]: (是否有效, 错误消息)
        """
        if not plaintext:
            return False, "明文数据为空"

        config = SEF_TYPE_CONFIG.get(data_type)
        if not config:
            return False, f"不支持的SEF数据类型: {data_type}"

        min_length = config.get('min_length', 1)
        if len(plaintext) < min_length:
            return False, f"数据长度不足，{data_type}类型至少需要{min_length}个字符"

        # 邮箱特殊验证
        if data_type == 'email':
            if '@' not in plaintext:
                return False, "邮箱格式无效，缺少@符号"

        return True, ""

    def encode(self, plaintext: str, data_type: str) -> str:
        """
        将明文编码为SEF格式字符串

        Args:
            plaintext: 原始明文数据
            data_type: 数据类型（如 'id_card', 'phone', 'name' 等）

        Returns:
            str: SEF格式字符串

        Raises:
            ValueError: 数据验证失败
        """
        if data_type not in SEF_TYPE_CONFIG:
            raise ValueError(f"不支持的SEF数据类型: {data_type}，"
                             f"支持的类型: {list(SEF_TYPE_CONFIG.keys())}")

        if not plaintext:
            return ''

        config = SEF_TYPE_CONFIG[data_type]
        prefix_len = config['visible_prefix']
        suffix_len = config['visible_suffix']

        # 邮箱特殊处理：保留域名可见
        if data_type == 'email' and config.get('preserve_domain'):
            return self._encode_email(plaintext, config)

        # 提取可见前缀和后缀
        visible_prefix = plaintext[:prefix_len] if prefix_len > 0 else ''
        visible_suffix = plaintext[-suffix_len:] if suffix_len > 0 else ''

        # 计算核心部分长度
        core_start = prefix_len
        core_end = len(plaintext) - suffix_len if suffix_len > 0 else len(plaintext)
        core = plaintext[core_start:core_end]

        # 处理核心为空或过短的情况
        if not core:
            # 数据太短，全部可见，不加密
            logger.warning(f"数据长度不足，{data_type}类型数据全部可见: {plaintext}")
            visible_prefix = plaintext
            visible_suffix = ''
            core = ''

        # 计算HMAC令牌（确定性，用于密文查询）
        hmac_token = self._compute_hmac(plaintext)

        # 加密核心部分（如果核心不为空）
        if core:
            encrypted_core = self.encryptor.encrypt_core(core)
        else:
            encrypted_core = 'EMPTY'  # 标记为空核心

        # 拼接SEF格式
        sef_string = SEF_DELIMITER.join([
            SEF_PREFIX,
            SEF_VERSION,
            data_type,
            visible_prefix,
            visible_suffix,
            hmac_token,
            encrypted_core,
        ])

        return sef_string

    def _encode_email(self, email: str, config: Dict) -> str:
        """
        邮箱特殊编码：域名部分可见不加密

        格式: SEF:v1:email:{prefix}:{domain}:{hmac}:{encrypted_local}

        Args:
            email: 邮箱地址
            config: 类型配置

        Returns:
            str: SEF格式字符串
        """
        if '@' not in email:
            raise ValueError(f"邮箱格式无效: {email}")

        local_part, domain = email.split('@', 1)
        prefix_len = config['visible_prefix']

        # 可见前缀（用户名前几个字符）
        visible_prefix = local_part[:prefix_len] if prefix_len > 0 else ''

        # 需要加密的核心部分（用户名剩余部分）
        core_local = local_part[prefix_len:] if prefix_len < len(local_part) else ''

        # HMAC令牌（基于完整邮箱）
        hmac_token = self._compute_hmac(email)

        # 加密核心部分
        if core_local:
            encrypted_core = self.encryptor.encrypt_core(core_local)
        else:
            encrypted_core = 'EMPTY'

        # 邮箱SEF格式：将域名放在suffix位置
        sef_string = SEF_DELIMITER.join([
            SEF_PREFIX,
            SEF_VERSION,
            'email',
            visible_prefix,
            domain,  # 域名作为"suffix"存储，可见不加密
            hmac_token,
            encrypted_core,
        ])

        return sef_string

    def decode_visible(self, sef_string: str) -> Dict[str, str]:
        """
        从SEF字符串提取可见部分（零解密操作）

        Args:
            sef_string: SEF格式字符串

        Returns:
            Dict包含: type, prefix, suffix, token, display_text
        """
        parsed = self.parse(sef_string)
        if not parsed:
            return {'type': '', 'prefix': '', 'suffix': '', 'token': '', 'display_text': sef_string}

        display_text = self._generate_display(parsed)
        return {
            'type': parsed['type'],
            'prefix': parsed['prefix'],
            'suffix': parsed['suffix'],
            'token': parsed['token'],
            'display_text': display_text,
        }

    def decode_full(self, sef_string: str) -> str:
        """
        完全解密SEF字符串，返回原始明文

        Args:
            sef_string: SEF格式字符串

        Returns:
            str: 原始明文

        Raises:
            ValueError: SEF格式无效
        """
        parsed = self.parse(sef_string)
        if not parsed:
            raise ValueError(f"无效的SEF格式: {sef_string[:50]}...")

        data_type = parsed['type']
        encrypted_core = parsed['encrypted_core']

        # 处理空核心
        if encrypted_core == 'EMPTY':
            core = ''
        else:
            try:
                core = self.encryptor.decrypt_core(encrypted_core)
            except Exception as e:
                logger.error(f"SEF核心解密失败: {e}")
                raise ValueError(f"SEF核心解密失败: {e}")

        # 邮箱特殊处理
        if data_type == 'email':
            # prefix + core + @ + domain(suffix)
            return parsed['prefix'] + core + '@' + parsed['suffix']

        # 通用拼接: prefix + core + suffix
        return parsed['prefix'] + core + parsed['suffix']

    def to_display(self, sef_string: str) -> str:
        """
        将SEF转为脱敏显示文本（零解密操作）

        这是SEF的核心创新：直接从密文格式生成脱敏文本，
        无需解密任何数据。

        Args:
            sef_string: SEF格式字符串

        Returns:
            str: 脱敏后的显示文本
        """
        parsed = self.parse(sef_string)
        if not parsed:
            return sef_string

        return self._generate_display(parsed)

    def verify_token(self, sef_string: str, plaintext: str) -> bool:
        """
        验证SEF中的HMAC令牌是否匹配给定明文

        用于等值查询：先计算明文的HMAC，再与SEF中的token比较。

        Args:
            sef_string: SEF格式字符串
            plaintext: 待验证的明文

        Returns:
            bool: 令牌是否匹配
        """
        parsed = self.parse(sef_string)
        if not parsed:
            return False

        expected_token = self._compute_hmac(plaintext)
        return hmac.compare_digest(parsed['token'], expected_token)

    def compute_search_token(self, plaintext: str) -> str:
        """
        计算明文的HMAC搜索令牌

        用于密文等值查询：计算明文的令牌，然后在数据库中
        搜索包含该令牌的SEF记录。

        Args:
            plaintext: 原始明文

        Returns:
            str: HMAC令牌（12字符十六进制）
        """
        return self._compute_hmac(plaintext)

    @staticmethod
    def is_sef(value: str) -> bool:
        """
        判断一个字符串是否是SEF格式

        Args:
            value: 待检查的字符串

        Returns:
            bool: 是否是SEF格式
        """
        if not value or not isinstance(value, str):
            return False
        return (value.startswith(f'{SEF_PREFIX}{SEF_DELIMITER}{SEF_VERSION}{SEF_DELIMITER}')
                and value.count(SEF_DELIMITER) >= 6)

    @staticmethod
    def parse(sef_string: str) -> Optional[Dict[str, str]]:
        """
        解析SEF字符串为结构化字典

        Args:
            sef_string: SEF格式字符串

        Returns:
            Dict包含: version, type, prefix, suffix, token, encrypted_core
            如果格式无效返回None
        """
        if not sef_string or not isinstance(sef_string, str):
            return None

        parts = sef_string.split(SEF_DELIMITER)
        # SEF:v1:type:prefix:suffix:token:encrypted_core = 7部分
        # 加密核心可能包含':'字符（base64不会，但保险起见取最后部分）
        if len(parts) < 7:
            return None

        if parts[0] != SEF_PREFIX or parts[1] != SEF_VERSION:
            return None

        return {
            'version': parts[1],
            'type': parts[2],
            'prefix': parts[3],
            'suffix': parts[4],
            'token': parts[5],
            'encrypted_core': SEF_DELIMITER.join(parts[6:]),
        }

    def _compute_hmac(self, plaintext: str) -> str:
        """
        计算HMAC-SHA256令牌

        Args:
            plaintext: 原始明文

        Returns:
            str: 截取的十六进制HMAC
        """
        h = hmac.new(
            self.hmac_key,
            plaintext.encode('utf-8'),
            hashlib.sha256
        )
        return h.hexdigest()[:HMAC_LENGTH]

    def _generate_display(self, parsed: Dict[str, str]) -> str:
        """
        根据解析结果和类型配置生成脱敏显示文本

        零解密操作：直接从SEF格式提取可见部分生成脱敏文本

        Args:
            parsed: parse()返回的字典

        Returns:
            str: 脱敏显示文本
        """
        data_type = parsed['type']
        prefix = parsed['prefix']
        suffix = parsed['suffix']

        config = SEF_TYPE_CONFIG.get(data_type)
        if not config:
            # 未知类型，返回前缀+星号
            return f'{prefix}***' if prefix else '***'

        pattern = config['mask_pattern']
        stars = '*' * config['star_count']

        # 邮箱特殊处理：suffix存储的是域名，零解密脱敏
        if data_type == 'email':
            domain = suffix  # 在新格式中，suffix存储域名
            if domain:
                return pattern.format(prefix=prefix, stars=stars, domain=domain)
            else:
                return f'{prefix}{stars}@***'

        # 地址特殊处理：加省略号
        if data_type == 'address':
            return f'{prefix}...' if prefix else '***'

        # 通用模式
        try:
            return pattern.format(prefix=prefix, stars=stars, suffix=suffix)
        except KeyError:
            return f'{prefix}{stars}{suffix}' if (prefix or suffix) else stars


class SEFQueryHelper:
    """
    SEF密文查询辅助器 — 支持在密文上做等值查询

    创新点：通过HMAC令牌实现"盲查询"——
    计算明文的HMAC，直接在数据库中匹配SEF记录的token字段，
    全程不接触明文数据。

    使用示例:
        helper = SEFQueryHelper(token_engine)

        # 搜索身份证号
        results = helper.search_by_token(
            db, 'students', 'id_card_sef', '320102199001011234'
        )
    """

    def __init__(self, token: StructuredToken):
        """
        初始化查询辅助器

        Args:
            token: StructuredToken实例
        """
        self.token = token

    def compute_search_token(self, plaintext: str) -> str:
        """
        计算明文的HMAC搜索令牌

        Args:
            plaintext: 原始明文

        Returns:
            str: HMAC令牌
        """
        return self.token.compute_search_token(plaintext)

    def search_by_token(self, db, table: str, sef_field: str,
                        plaintext: str) -> List[Dict]:
        """
        通过HMAC令牌在SEF列中搜索匹配记录

        在SEF格式中，HMAC令牌位于第6个字段（索引5）。
        使用LIKE查询匹配包含该令牌的记录。

        Args:
            db: DatabaseManager实例
            table: 表名
            sef_field: SEF列名（如 'id_card_sef'）
            plaintext: 搜索的明文值

        Returns:
            List[Dict]: 匹配的记录列表
        """
        search_token = self.compute_search_token(plaintext)
        # SEF格式中token位于第6个':'分隔的部分
        # 使用LIKE匹配包含该token的SEF字段
        pattern = f'%:{search_token}:%'
        query = f'SELECT * FROM {table} WHERE {sef_field} LIKE ?'
        return db.fetch_all(query, (pattern,))

    def search_exact(self, db, table: str, sef_field: str,
                     plaintext: str) -> Optional[Dict]:
        """
        精确搜索单条记录

        Args:
            db: DatabaseManager实例
            table: 表名
            sef_field: SEF列名
            plaintext: 搜索的明文值

        Returns:
            Optional[Dict]: 匹配的记录或None
        """
        search_token = self.compute_search_token(plaintext)
        pattern = f'%:{search_token}:%'
        query = f'SELECT * FROM {table} WHERE {sef_field} LIKE ? LIMIT 1'
        return db.fetch_one(query, (pattern,))


def get_sef_type_info() -> Dict[str, Dict]:
    """
    获取所有SEF类型配置信息（用于演示和文档）

    Returns:
        Dict: 类型配置字典
    """
    return {
        k: {
            'description': v['description'],
            'visible_prefix': v['visible_prefix'],
            'visible_suffix': v['visible_suffix'],
            'mask_pattern': v['mask_pattern'],
            'example': v['example'],
            'min_length': v.get('min_length', 1),
        }
        for k, v in SEF_TYPE_CONFIG.items()
    }
