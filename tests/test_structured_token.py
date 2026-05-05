#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SEF结构化加密格式单元测试

测试覆盖：
- 编码/解码往返一致性
- 可见部分提取
- 脱敏显示文本生成
- HMAC令牌一致性
- 不同数据类型
- 密文等值查询
- 向后兼容性
"""

import sys
import os
import pytest

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encryption import SM4Encryptor
from core.structured_token import StructuredToken, SEFQueryHelper, SEF_TYPE_CONFIG, get_sef_type_info


@pytest.fixture
def encryptor():
    """创建固定密钥的加密器"""
    return SM4Encryptor('0123456789abcdeffedcba9876543210')


@pytest.fixture
def token(encryptor):
    """创建StructuredToken实例"""
    return StructuredToken(encryptor)


@pytest.fixture
def query_helper(token):
    """创建SEFQueryHelper实例"""
    return SEFQueryHelper(token)


class TestSEFEncodeDecode:
    """SEF编码/解码测试"""

    def test_encode_decode_roundtrip_id_card(self, token):
        """身份证号编码后解密应得回原文"""
        plaintext = '320102199001011234'
        sef = token.encode(plaintext, 'id_card')
        assert token.decode_full(sef) == plaintext

    def test_encode_decode_roundtrip_phone(self, token):
        """手机号编码后解密应得回原文"""
        plaintext = '13812345678'
        sef = token.encode(plaintext, 'phone')
        assert token.decode_full(sef) == plaintext

    def test_encode_decode_roundtrip_email(self, token):
        """邮箱编码后解密应得回原文"""
        plaintext = 'zhangsan@example.com'
        sef = token.encode(plaintext, 'email')
        assert token.decode_full(sef) == plaintext

    def test_encode_decode_roundtrip_name(self, token):
        """姓名编码后解密应得回原文"""
        plaintext = '张三'
        sef = token.encode(plaintext, 'name')
        assert token.decode_full(sef) == plaintext

    def test_encode_decode_roundtrip_salary(self, token):
        """薪资编码后解密应得回原文"""
        plaintext = '15000'
        sef = token.encode(plaintext, 'salary')
        assert token.decode_full(sef) == plaintext

    def test_encode_decode_roundtrip_address(self, token):
        """地址编码后解密应得回原文"""
        plaintext = '江苏省南京市鼓楼区100号'
        sef = token.encode(plaintext, 'address')
        assert token.decode_full(sef) == plaintext

    def test_encode_decode_roundtrip_bank_card(self, token):
        """银行卡号编码后解密应得回原文"""
        plaintext = '6222021234567890123'
        sef = token.encode(plaintext, 'bank_card')
        assert token.decode_full(sef) == plaintext

    def test_encode_empty_string(self, token):
        """空字符串编码应返回空"""
        assert token.encode('', 'id_card') == ''
        assert token.encode(None, 'id_card') == ''

    def test_encode_unsupported_type(self, token):
        """不支持的数据类型应抛出异常"""
        with pytest.raises(ValueError):
            token.encode('test', 'unsupported_type')


class TestSEFVisibleExtraction:
    """SEF可见部分提取测试"""

    def test_id_card_visible(self, token):
        """身份证号可见前缀6位后缀4位"""
        sef = token.encode('320102199001011234', 'id_card')
        visible = token.decode_visible(sef)
        assert visible['prefix'] == '320102'
        assert visible['suffix'] == '1234'
        assert visible['type'] == 'id_card'

    def test_phone_visible(self, token):
        """手机号可见前缀3位后缀4位"""
        sef = token.encode('13812345678', 'phone')
        visible = token.decode_visible(sef)
        assert visible['prefix'] == '138'
        assert visible['suffix'] == '5678'

    def test_email_visible(self, token):
        """邮箱可见前缀3字符，域名存储在suffix中"""
        sef = token.encode('zhangsan@example.com', 'email')
        visible = token.decode_visible(sef)
        assert visible['prefix'] == 'zha'
        # 新格式：suffix存储域名，实现零解密脱敏
        assert visible['suffix'] == 'example.com'

    def test_name_visible(self, token):
        """姓名可见姓氏"""
        sef = token.encode('张三', 'name')
        visible = token.decode_visible(sef)
        assert visible['prefix'] == '张'

    def test_salary_no_visible(self, token):
        """薪资无可见部分"""
        sef = token.encode('15000', 'salary')
        visible = token.decode_visible(sef)
        assert visible['prefix'] == ''
        assert visible['suffix'] == ''


class TestSEFDisplay:
    """SEF脱敏显示测试"""

    def test_id_card_display(self, token):
        """身份证号脱敏显示"""
        sef = token.encode('320102199001011234', 'id_card')
        display = token.to_display(sef)
        assert display == '320102********1234'

    def test_phone_display(self, token):
        """手机号脱敏显示"""
        sef = token.encode('13812345678', 'phone')
        display = token.to_display(sef)
        assert display == '138****5678'

    def test_email_display(self, token):
        """邮箱脱敏显示"""
        sef = token.encode('zhangsan@example.com', 'email')
        display = token.to_display(sef)
        assert display == 'zha******@example.com'

    def test_name_display(self, token):
        """姓名脱敏显示"""
        sef = token.encode('张三', 'name')
        display = token.to_display(sef)
        assert display == '张*'

    def test_salary_display(self, token):
        """薪资脱敏显示"""
        sef = token.encode('15000', 'salary')
        display = token.to_display(sef)
        assert display == '******'

    def test_address_display(self, token):
        """地址脱敏显示"""
        sef = token.encode('江苏省南京市鼓楼区100号', 'address')
        display = token.to_display(sef)
        assert display == '江苏省南京市...'

    def test_display_non_sef(self, token):
        """非SEF字符串原样返回"""
        assert token.to_display('hello') == 'hello'
        assert token.to_display('') == ''


class TestSEFHMACToken:
    """SEF HMAC令牌测试"""

    def test_hmac_consistency(self, token):
        """同一明文HMAC应一致"""
        t1 = token.compute_search_token('320102199001011234')
        t2 = token.compute_search_token('320102199001011234')
        assert t1 == t2

    def test_hmac_different_plaintext(self, token):
        """不同明文HMAC应不同"""
        t1 = token.compute_search_token('320102199001011234')
        t2 = token.compute_search_token('320102199001011235')
        assert t1 != t2

    def test_hmac_length(self, token):
        """HMAC长度应为12字符"""
        t = token.compute_search_token('test')
        assert len(t) == 12

    def test_verify_token_correct(self, token):
        """正确明文验证应通过"""
        sef = token.encode('320102199001011234', 'id_card')
        assert token.verify_token(sef, '320102199001011234') is True

    def test_verify_token_wrong(self, token):
        """错误明文验证应失败"""
        sef = token.encode('320102199001011234', 'id_card')
        assert token.verify_token(sef, '320102199001011235') is False

    def test_search_token_matches_sef(self, token):
        """搜索令牌应与SEF中的token一致"""
        sef = token.encode('320102199001011234', 'id_card')
        parsed = StructuredToken.parse(sef)
        search_token = token.compute_search_token('320102199001011234')
        assert search_token == parsed['token']


class TestSEFParse:
    """SEF格式解析测试"""

    def test_parse_valid(self, token):
        """有效SEF应正确解析"""
        sef = token.encode('320102199001011234', 'id_card')
        parsed = StructuredToken.parse(sef)
        assert parsed is not None
        assert parsed['version'] == 'v1'
        assert parsed['type'] == 'id_card'
        assert parsed['prefix'] == '320102'
        assert parsed['suffix'] == '1234'

    def test_parse_invalid(self):
        """无效SEF应返回None"""
        assert StructuredToken.parse('') is None
        assert StructuredToken.parse(None) is None
        assert StructuredToken.parse('hello') is None
        assert StructuredToken.parse('SEF:v1') is None

    def test_is_sef_valid(self, token):
        """有效SEF应被识别"""
        sef = token.encode('test', 'name')
        assert StructuredToken.is_sef(sef) is True

    def test_is_sef_invalid(self):
        """非SEF应不被识别"""
        assert StructuredToken.is_sef('') is False
        assert StructuredToken.is_sef(None) is False
        assert StructuredToken.is_sef('hello') is False
        assert StructuredToken.is_sef('SEF:v1') is False


class TestSEFDifferentTypes:
    """不同数据类型测试"""

    @pytest.mark.parametrize("plaintext,data_type", [
        ('320102199001011234', 'id_card'),
        ('13812345678', 'phone'),
        ('zhangsan@example.com', 'email'),
        ('张三', 'name'),
        ('15000', 'salary'),
        ('6222021234567890123', 'bank_card'),
        ('江苏省南京市鼓楼区100号', 'address'),
    ])
    def test_roundtrip(self, token, plaintext, data_type):
        """所有类型编码解码往返一致"""
        sef = token.encode(plaintext, data_type)
        assert token.decode_full(sef) == plaintext

    @pytest.mark.parametrize("plaintext,data_type", [
        ('320102199001011234', 'id_card'),
        ('13812345678', 'phone'),
        ('zhangsan@example.com', 'email'),
        ('张三', 'name'),
        ('15000', 'salary'),
    ])
    def test_display_not_empty(self, token, plaintext, data_type):
        """所有类型脱敏显示不为空"""
        sef = token.encode(plaintext, data_type)
        display = token.to_display(sef)
        assert len(display) > 0
        assert display != plaintext  # 脱敏后不应等于原文

    def test_sef_format_structure(self, token):
        """SEF格式应有7个冒号分隔部分"""
        sef = token.encode('320102199001011234', 'id_card')
        parts = sef.split(':')
        assert len(parts) >= 7
        assert parts[0] == 'SEF'
        assert parts[1] == 'v1'


class TestSEFQueryHelper:
    """SEF密文查询测试"""

    def test_compute_search_token(self, query_helper, token):
        """查询令牌应与SEF令牌一致"""
        plaintext = '320102199001011234'
        sef = token.encode(plaintext, 'id_card')
        parsed = StructuredToken.parse(sef)
        search_token = query_helper.compute_search_token(plaintext)
        assert search_token == parsed['token']

    def test_search_token_different_for_different_values(self, query_helper):
        """不同值的查询令牌应不同"""
        t1 = query_helper.compute_search_token('320102199001011234')
        t2 = query_helper.compute_search_token('13812345678')
        assert t1 != t2


class TestSEFBackwardCompatibility:
    """向后兼容性测试"""

    def test_non_sef_string_handling(self, token):
        """非SEF字符串应被安全处理"""
        assert StructuredToken.is_sef('old_encrypted_data') is False
        assert token.to_display('old_encrypted_data') == 'old_encrypted_data'

    def test_different_keys_different_sef(self, encryptor):
        """不同密钥生成不同SEF"""
        token1 = StructuredToken(SM4Encryptor('00000000000000000000000000000001'))
        token2 = StructuredToken(SM4Encryptor('00000000000000000000000000000002'))

        sef1 = token1.encode('320102199001011234', 'id_card')
        sef2 = token2.encode('320102199001011234', 'id_card')

        # 可见部分应相同（不依赖密钥）
        assert StructuredToken.parse(sef1)['prefix'] == StructuredToken.parse(sef2)['prefix']
        assert StructuredToken.parse(sef1)['suffix'] == StructuredToken.parse(sef2)['suffix']

        # 加密核心应不同（依赖密钥）
        assert StructuredToken.parse(sef1)['encrypted_core'] != StructuredToken.parse(sef2)['encrypted_core']

        # HMAC令牌应不同（依赖密钥）
        assert StructuredToken.parse(sef1)['token'] != StructuredToken.parse(sef2)['token']


class TestSEFTypeInfo:
    """SEF类型信息测试"""

    def test_get_sef_type_info(self):
        """应返回所有类型信息"""
        info = get_sef_type_info()
        assert 'id_card' in info
        assert 'phone' in info
        assert 'email' in info
        assert 'name' in info
        assert 'salary' in info
        assert 'description' in info['id_card']

    def test_all_types_have_config(self):
        """所有类型应有完整配置"""
        for type_name, config in SEF_TYPE_CONFIG.items():
            assert 'visible_prefix' in config
            assert 'visible_suffix' in config
            assert 'mask_pattern' in config
            assert 'description' in config


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
