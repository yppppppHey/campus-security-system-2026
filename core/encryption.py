#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
国密SM4加密模块
实现符合国密标准的SM4对称加密算法

功能:
    - SM4加密/解密
    - 文件加密/解密
    - 密钥管理
    - 加密数据存储

参考标准: GM/T 0002-2012 SM4分组密码算法
"""

import os
import struct
import base64
import hashlib
import secrets
from typing import Tuple, Optional, Union, List
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class SM4:
    """
    SM4加密算法实现
    国密SM4分组密码算法，分组长度128位，密钥长度128位
    """

    # SM4算法参数
    BLOCK_SIZE = 16  # 分组大小（字节）
    KEY_SIZE = 16    # 密钥大小（字节）
    ROUNDS = 32      # 轮数

    # 系统参数FK
    FK = [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc]

    # 固定参数CK
    CK = [
        0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
        0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
        0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
        0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
        0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
        0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
        0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
        0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
    ]

    # S盒
    SBOX = [
        0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
        0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xea, 0x71, 0xb7, 0x93, 0x80, 0x66, 0x48, 0x8f,
        0x96, 0x11, 0xd9, 0xc8, 0x43, 0xa5, 0x00, 0x87, 0xbc, 0x9d, 0x6f, 0x16, 0xa7, 0x92, 0xde, 0xe0,
        0x90, 0x9d, 0x4d, 0x38, 0xf5, 0xbc, 0xf6, 0xda, 0x21, 0x60, 0xd0, 0x29, 0x94, 0x70, 0x96, 0x2e,
        0x4e, 0xb7, 0x58, 0xe6, 0x21, 0x54, 0x32, 0x0e, 0x98, 0x3b, 0xb0, 0x6b, 0x55, 0x2c, 0x9d, 0xca,
        0xb4, 0x36, 0xb3, 0x38, 0xd3, 0x5d, 0x8a, 0xf9, 0x35, 0x7f, 0x6d, 0x54, 0xc2, 0x46, 0x6c, 0x70,
        0x64, 0x80, 0x86, 0x97, 0x5b, 0xbb, 0x6f, 0x9e, 0x4c, 0x66, 0x5b, 0x13, 0x7d, 0x74, 0x3b, 0x71,
        0xd8, 0x31, 0xa4, 0x73, 0xa0, 0x3a, 0xba, 0x5f, 0x2d, 0x78, 0x00, 0x7f, 0x67, 0x51, 0xbe, 0x17,
        0x6b, 0x3d, 0x76, 0x3c, 0xb4, 0x7c, 0x3e, 0x5b, 0x4f, 0x69, 0x61, 0x2e, 0x8b, 0x52, 0x7b, 0xd1,
        0xe3, 0x23, 0x5d, 0x18, 0x96, 0x1e, 0x58, 0x3d, 0x22, 0x06, 0x75, 0x22, 0x71, 0x5d, 0x69, 0x33,
        0x48, 0x3b, 0x78, 0x4c, 0x78, 0x5c, 0xc0, 0x32, 0x28, 0x5e, 0x85, 0xda, 0x9d, 0x5d, 0x56, 0x6f,
        0x4c, 0x31, 0x2d, 0x5f, 0xb7, 0x69, 0x9a, 0x57, 0x62, 0xdf, 0x32, 0x58, 0x49, 0x6b, 0xd1, 0x75,
        0x8b, 0xc5, 0x6d, 0x9b, 0x51, 0xc9, 0x4a, 0x8f, 0x13, 0xb6, 0x89, 0x88, 0x3d, 0x76, 0xa5, 0xf1,
        0x6b, 0xd8, 0x3a, 0x9d, 0x52, 0x6f, 0xda, 0xad, 0xa5, 0x7a, 0x48, 0x7d, 0x54, 0x70, 0xa7, 0x8d,
        0x65, 0x4d, 0x76, 0x87, 0x13, 0x6f, 0x25, 0x38, 0xf1, 0x5b, 0x2c, 0x3d, 0x65, 0x1d, 0x5b, 0x2c,
        0x93, 0x04, 0x23, 0x58, 0x64, 0xfa, 0xa4, 0x27, 0x2c, 0x7a, 0x58, 0x73, 0x42, 0x23, 0x6b, 0x18,
        0x8f, 0x60, 0x03, 0x6b, 0x37, 0x06, 0x86, 0xf2, 0x30, 0x89, 0x30, 0xc5, 0x6d, 0xc7, 0x76, 0x51,
        0xa1, 0x2c, 0x5a, 0x8b, 0x04, 0x57, 0x55, 0x38, 0x7c, 0x63, 0x58, 0xd3, 0x50, 0x24, 0xb1, 0x5b,
        0xa7, 0x46, 0x3d, 0x7d, 0x39, 0x38, 0x21, 0x40, 0x53, 0x99, 0x2f, 0xda, 0xa4, 0x20, 0x98, 0x23,
        0x91, 0x38, 0xe6, 0xdb, 0x69, 0xa1, 0x3b, 0x16, 0x6b, 0x4b, 0x9b, 0x10, 0x6d, 0x6f, 0x5a, 0x01
    ]

    def __init__(self, key: bytes):
        """
        初始化SM4

        Args:
            key: 16字节密钥
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"密钥长度必须为{self.KEY_SIZE}字节")

        self.key = key
        self.round_keys = self._generate_round_keys(key)

    def _sbox_lookup(self, x: int) -> int:
        """S盒查表"""
        return self.SBOX[x]

    def _nonlinear_transform(self, x: int) -> int:
        """
        非线性变换τ
        将32位输入分成4个字节，每个字节分别通过S盒，然后重新组合
        τ(x) = (S(x0) << 24) | (S(x1) << 16) | (S(x2) << 8) | S(x3)
        其中 x0, x1, x2, x3 是 x 的4个字节（大端序）
        """
        # 将32位整数拆分成4个字节
        b0 = (x >> 24) & 0xff
        b1 = (x >> 16) & 0xff
        b2 = (x >> 8) & 0xff
        b3 = x & 0xff

        # 每个字节通过S盒
        s0 = self._sbox_lookup(b0)
        s1 = self._sbox_lookup(b1)
        s2 = self._sbox_lookup(b2)
        s3 = self._sbox_lookup(b3)

        # 重新组合成32位整数（仅非线性变换）
        return (s0 << 24) | (s1 << 16) | (s2 << 8) | s3

    def _linear_transform(self, x: int) -> int:
        """
        线性变换L
        L(x) = x ⊕ (x <<< 2) ⊕ (x <<< 10) ⊕ (x <<< 18) ⊕ (x <<< 24)
        """
        return x ^ self._rotl(x, 2) ^ self._rotl(x, 10) ^ self._rotl(x, 18) ^ self._rotl(x, 24)

    def _linear_transform_prime(self, x: int) -> int:
        """
        线性变换L'
        L'(x) = x ⊕ (x <<< 9) ⊕ (x <<< 14)
        """
        return x ^ self._rotl(x, 9) ^ self._rotl(x, 14)

    @staticmethod
    def _rotl(x: int, n: int) -> int:
        """32位循环左移"""
        return ((x << n) | (x >> (32 - n))) & 0xffffffff

    def _t_transform(self, x: int) -> int:
        """合成变换T"""
        return self._linear_transform(self._nonlinear_transform(x))

    def _t_transform_prime(self, x: int) -> int:
        """合成变换T'"""
        return self._linear_transform_prime(self._nonlinear_transform(x))

    def _generate_round_keys(self, key: bytes) -> List[int]:
        """
        生成轮密钥

        Args:
            key: 原始密钥

        Returns:
            List[int]: 32个轮密钥
        """
        # 将密钥分为4个字
        mk = struct.unpack('>4I', key)

        # 计算K
        k = [mk[i] ^ self.FK[i] for i in range(4)]

        # 生成轮密钥
        rk = []
        for i in range(self.ROUNDS):
            tmp = k[1] ^ k[2] ^ k[3] ^ self.CK[i]
            k_new = k[0] ^ self._t_transform_prime(tmp)
            rk.append(k_new)
            k = [k[1], k[2], k[3], k_new]

        return rk

    def _encrypt_block(self, block: bytes) -> bytes:
        """
        加密一个分组

        Args:
            block: 16字节明文分组

        Returns:
            bytes: 16字节密文分组
        """
        # 将分组转为4个字
        x = list(struct.unpack('>4I', block))

        # 32轮加密
        for i in range(self.ROUNDS):
            tmp = x[1] ^ x[2] ^ x[3] ^ self.round_keys[i]
            x_new = x[0] ^ self._t_transform(tmp)
            x = [x[1], x[2], x[3], x_new]

        # 反序变换R
        y = [x[3], x[2], x[1], x[0]]

        return struct.pack('>4I', *y)

    def _decrypt_block(self, block: bytes) -> bytes:
        """
        解密一个分组

        Args:
            block: 16字节密文分组

        Returns:
            bytes: 16字节明文分组
        """
        # 将分组转为4个字
        x = list(struct.unpack('>4I', block))

        # 32轮解密（使用逆序轮密钥）
        for i in range(self.ROUNDS - 1, -1, -1):
            tmp = x[1] ^ x[2] ^ x[3] ^ self.round_keys[i]
            x_new = x[0] ^ self._t_transform(tmp)
            x = [x[1], x[2], x[3], x_new]

        # 反序变换R
        y = [x[3], x[2], x[1], x[0]]

        return struct.pack('>4I', *y)


class SM4Encryptor:
    """
    SM4加密器
    提供完整的加密功能，支持多种加密模式
    """

    # 加密模式
    MODE_ECB = 'ECB'  # 电子密码本模式
    MODE_CBC = 'CBC'  # 密码分组链接模式
    MODE_CTR = 'CTR'  # 计数器模式

    def __init__(self, key: Union[str, bytes] = None):
        """
        初始化SM4加密器

        Args:
            key: 密钥，可以是十六进制字符串或字节
                 如果为None，则自动生成随机密钥
        """
        if key is None:
            self.key = secrets.token_bytes(SM4.KEY_SIZE)
        elif isinstance(key, str):
            # 十六进制字符串转字节
            self.key = bytes.fromhex(key.zfill(32))[:SM4.KEY_SIZE]
        else:
            self.key = key[:SM4.KEY_SIZE]

        if len(self.key) != SM4.KEY_SIZE:
            raise ValueError(f"密钥长度必须为{SM4.KEY_SIZE}字节")

        self.sm4 = SM4(self.key)
        logger.info("SM4加密器初始化完成")

    def get_key_hex(self) -> str:
        """获取十六进制格式密钥"""
        return self.key.hex()

    @staticmethod
    def generate_key() -> bytes:
        """生成随机密钥"""
        return secrets.token_bytes(SM4.KEY_SIZE)

    def _pkcs7_pad(self, data: bytes) -> bytes:
        """PKCS7填充"""
        pad_len = SM4.BLOCK_SIZE - (len(data) % SM4.BLOCK_SIZE)
        return data + bytes([pad_len] * pad_len)

    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """去除PKCS7填充"""
        if not data:
            return data
        pad_len = data[-1]
        if pad_len > SM4.BLOCK_SIZE or pad_len == 0:
            return data
        # 验证填充
        if data[-pad_len:] != bytes([pad_len] * pad_len):
            return data
        return data[:-pad_len]

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """字节异或"""
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt_ecb(self, plaintext: bytes) -> bytes:
        """
        ECB模式加密

        Args:
            plaintext: 明文

        Returns:
            bytes: 密文
        """
        padded = self._pkcs7_pad(plaintext)
        ciphertext = b''

        for i in range(0, len(padded), SM4.BLOCK_SIZE):
            block = padded[i:i + SM4.BLOCK_SIZE]
            ciphertext += self.sm4._encrypt_block(block)

        return ciphertext

    def decrypt_ecb(self, ciphertext: bytes) -> bytes:
        """
        ECB模式解密

        Args:
            ciphertext: 密文

        Returns:
            bytes: 明文
        """
        if len(ciphertext) % SM4.BLOCK_SIZE != 0:
            raise ValueError("密文长度必须是分组大小的整数倍")

        plaintext = b''

        for i in range(0, len(ciphertext), SM4.BLOCK_SIZE):
            block = ciphertext[i:i + SM4.BLOCK_SIZE]
            plaintext += self.sm4._decrypt_block(block)

        return self._pkcs7_unpad(plaintext)

    def encrypt_cbc(self, plaintext: bytes, iv: bytes = None) -> Tuple[bytes, bytes]:
        """
        CBC模式加密

        Args:
            plaintext: 明文
            iv: 初始化向量，为None时自动生成

        Returns:
            Tuple[bytes, bytes]: (密文, IV)
        """
        if iv is None:
            iv = secrets.token_bytes(SM4.BLOCK_SIZE)
        elif len(iv) != SM4.BLOCK_SIZE:
            raise ValueError("IV长度必须为分组大小")

        padded = self._pkcs7_pad(plaintext)
        ciphertext = b''
        prev_block = iv

        for i in range(0, len(padded), SM4.BLOCK_SIZE):
            block = padded[i:i + SM4.BLOCK_SIZE]
            # 先与前一个密文块异或
            xored = self._xor_bytes(block, prev_block)
            # 再加密
            encrypted = self.sm4._encrypt_block(xored)
            ciphertext += encrypted
            prev_block = encrypted

        return ciphertext, iv

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        CBC模式解密

        Args:
            ciphertext: 密文
            iv: 初始化向量

        Returns:
            bytes: 明文
        """
        if len(ciphertext) % SM4.BLOCK_SIZE != 0:
            raise ValueError("密文长度必须是分组大小的整数倍")
        if len(iv) != SM4.BLOCK_SIZE:
            raise ValueError("IV长度必须为分组大小")

        plaintext = b''
        prev_block = iv

        for i in range(0, len(ciphertext), SM4.BLOCK_SIZE):
            block = ciphertext[i:i + SM4.BLOCK_SIZE]
            # 解密
            decrypted = self.sm4._decrypt_block(block)
            # 与前一个密文块异或
            plaintext += self._xor_bytes(decrypted, prev_block)
            prev_block = block

        return self._pkcs7_unpad(plaintext)

    def encrypt_ctr(self, plaintext: bytes, nonce: bytes = None) -> Tuple[bytes, bytes]:
        """
        CTR模式加密

        Args:
            plaintext: 明文
            nonce: 随机数，为None时自动生成

        Returns:
            Tuple[bytes, bytes]: (密文, nonce)
        """
        if nonce is None:
            nonce = secrets.token_bytes(SM4.BLOCK_SIZE)
        elif len(nonce) != SM4.BLOCK_SIZE:
            raise ValueError("nonce长度必须为分组大小")

        ciphertext = b''
        counter = 0

        for i in range(0, len(plaintext), SM4.BLOCK_SIZE):
            # 生成计数器块
            ctr_block = nonce[:12] + counter.to_bytes(4, 'big')
            # 加密计数器块
            keystream = self.sm4._encrypt_block(ctr_block)
            # 与明文异或
            block = plaintext[i:i + SM4.BLOCK_SIZE]
            ciphertext += self._xor_bytes(block, keystream[:len(block)])
            counter += 1

        return ciphertext, nonce

    def decrypt_ctr(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """
        CTR模式解密（与加密相同）

        Args:
            ciphertext: 密文
            nonce: 随机数

        Returns:
            bytes: 明文
        """
        return self.encrypt_ctr(ciphertext, nonce)[0]

    def encrypt(self, plaintext: Union[str, bytes], mode: str = MODE_CBC) -> str:
        """
        加密数据（便捷方法）

        Args:
            plaintext: 明文
            mode: 加密模式

        Returns:
            str: Base64编码的密文（包含IV和模式信息）
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        if mode == self.MODE_ECB:
            ciphertext = self.encrypt_ecb(plaintext)
            result = b'ECB' + ciphertext
        elif mode == self.MODE_CBC:
            ciphertext, iv = self.encrypt_cbc(plaintext)
            result = b'CBC' + iv + ciphertext
        elif mode == self.MODE_CTR:
            ciphertext, nonce = self.encrypt_ctr(plaintext)
            result = b'CTR' + nonce + ciphertext
        else:
            raise ValueError(f"不支持的加密模式: {mode}")

        return base64.b64encode(result).decode('ascii')

    def decrypt(self, ciphertext: str) -> str:
        """
        解密数据（便捷方法）

        Args:
            ciphertext: Base64编码的密文

        Returns:
            str: 明文
        """
        data = base64.b64decode(ciphertext)

        mode = data[:3].decode('ascii')

        if mode == 'ECB':
            plaintext = self.decrypt_ecb(data[3:])
        elif mode == 'CBC':
            iv = data[3:19]
            plaintext = self.decrypt_cbc(data[19:], iv)
        elif mode == 'CTR':
            nonce = data[3:19]
            plaintext = self.decrypt_ctr(data[19:], nonce)
        else:
            raise ValueError(f"未知的加密模式: {mode}")

        return plaintext.decode('utf-8')

    def encrypt_core(self, plaintext: Union[str, bytes]) -> str:
        """
        加密核心数据（用于SEF结构化令牌）

        使用CBC模式，返回Base64编码的密文

        Args:
            plaintext: 明文

        Returns:
            str: Base64编码的密文（包含IV）
        """
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        ciphertext, iv = self.encrypt_cbc(plaintext)
        # 将IV和密文一起编码
        result = iv + ciphertext
        return base64.b64encode(result).decode('ascii')

    def decrypt_core(self, ciphertext: str) -> str:
        """
        解密核心数据（用于SEF结构化令牌）

        Args:
            ciphertext: Base64编码的密文（包含IV）

        Returns:
            str: 明文
        """
        data = base64.b64decode(ciphertext)

        # IV在前16字节，密文在后
        iv = data[:16]
        encrypted = data[16:]

        plaintext = self.decrypt_cbc(encrypted, iv)
        return plaintext.decode('utf-8')

    def encrypt_file(self, input_path: str, output_path: str,
                     mode: str = MODE_CBC) -> Tuple[bool, str]:
        """
        加密文件

        Args:
            input_path: 输入文件路径
            output_path: 输出文件路径
            mode: 加密模式

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        try:
            with open(input_path, 'rb') as f:
                plaintext = f.read()

            if mode == self.MODE_CBC:
                ciphertext, iv = self.encrypt_cbc(plaintext)
                result = b'SM4_CBC' + iv + ciphertext
            elif mode == self.MODE_CTR:
                ciphertext, nonce = self.encrypt_ctr(plaintext)
                result = b'SM4_CTR' + nonce + ciphertext
            else:
                result = b'SM4_ECB' + self.encrypt_ecb(plaintext)

            with open(output_path, 'wb') as f:
                f.write(result)

            logger.info(f"文件加密成功: {input_path} -> {output_path}")
            return True, "文件加密成功"

        except Exception as e:
            logger.error(f"文件加密失败: {e}")
            return False, f"加密失败: {str(e)}"

    def decrypt_file(self, input_path: str, output_path: str) -> Tuple[bool, str]:
        """
        解密文件

        Args:
            input_path: 输入文件路径
            output_path: 输出文件路径

        Returns:
            Tuple[bool, str]: (是否成功, 消息)
        """
        try:
            with open(input_path, 'rb') as f:
                data = f.read()

            header = data[:7].decode('ascii')

            if header == 'SM4_CBC':
                iv = data[7:23]
                plaintext = self.decrypt_cbc(data[23:], iv)
            elif header == 'SM4_CTR':
                nonce = data[7:23]
                plaintext = self.decrypt_ctr(data[23:], nonce)
            elif header == 'SM4_ECB':
                plaintext = self.decrypt_ecb(data[7:])
            else:
                return False, "未知的文件加密格式"

            with open(output_path, 'wb') as f:
                f.write(plaintext)

            logger.info(f"文件解密成功: {input_path} -> {output_path}")
            return True, "文件解密成功"

        except Exception as e:
            logger.error(f"文件解密失败: {e}")
            return False, f"解密失败: {str(e)}"

    def encrypt_dict(self, data: dict, fields: List[str]) -> dict:
        """
        加密字典中的指定字段

        Args:
            data: 数据字典
            fields: 需要加密的字段列表

        Returns:
            dict: 加密后的数据
        """
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                result[field] = self.encrypt(str(result[field]))
        return result

    def decrypt_dict(self, data: dict, fields: List[str]) -> dict:
        """
        解密字典中的指定字段

        Args:
            data: 数据字典
            fields: 需要解密的的字段列表

        Returns:
            dict: 解密后的数据
        """
        result = data.copy()
        for field in fields:
            if field in result and result[field]:
                try:
                    result[field] = self.decrypt(result[field])
                except Exception:
                    pass  # 解密失败保留原值
        return result


class KeyManager:
    """
    密钥管理器
    提供密钥的生成、存储、派生等功能
    """

    def __init__(self, master_key: bytes = None):
        """
        初始化密钥管理器

        Args:
            master_key: 主密钥
        """
        self.master_key = master_key or secrets.token_bytes(32)

    def derive_key(self, context: str, key_id: str = None) -> bytes:
        """
        派生子密钥

        Args:
            context: 上下文信息
            key_id: 密钥标识

        Returns:
            bytes: 派生的密钥
        """
        info = f"{context}:{key_id or ''}".encode('utf-8')
        # 使用HMAC进行密钥派生
        derived = hashlib.pbkdf2_hmac(
            'sha256',
            self.master_key,
            info,
            iterations=10000,
            dklen=16
        )
        return derived

    def generate_key_pair(self) -> Tuple[str, bytes, bytes]:
        """
        生成密钥对（用于标识和密钥）

        Returns:
            Tuple[str, bytes, bytes]: (密钥ID, 加密密钥, 备份密钥)
        """
        key_id = secrets.token_hex(16)
        encrypt_key = secrets.token_bytes(16)
        backup_key = self.derive_key('backup', key_id)
        return key_id, encrypt_key, backup_key


if __name__ == '__main__':
    # 测试SM4加密
    print("=" * 50)
    print("SM4加密算法测试")
    print("=" * 50)

    # 创建加密器
    encryptor = SM4Encryptor()
    print(f"密钥: {encryptor.get_key_hex()}")

    # 测试字符串加密
    plaintext = "这是一段测试文本，用于验证SM4加密算法的正确性。Campus Security System 2024"
    print(f"\n原文: {plaintext}")

    # ECB模式
    encrypted_ecb = encryptor.encrypt(plaintext, SM4Encryptor.MODE_ECB)
    print(f"\nECB加密: {encrypted_ecb[:50]}...")
    decrypted_ecb = encryptor.decrypt(encrypted_ecb)
    print(f"ECB解密: {decrypted_ecb}")
    print(f"ECB验证: {'成功' if decrypted_ecb == plaintext else '失败'}")

    # CBC模式
    encrypted_cbc = encryptor.encrypt(plaintext, SM4Encryptor.MODE_CBC)
    print(f"\nCBC加密: {encrypted_cbc[:50]}...")
    decrypted_cbc = encryptor.decrypt(encrypted_cbc)
    print(f"CBC解密: {decrypted_cbc}")
    print(f"CBC验证: {'成功' if decrypted_cbc == plaintext else '失败'}")

    # CTR模式
    encrypted_ctr = encryptor.encrypt(plaintext, SM4Encryptor.MODE_CTR)
    print(f"\nCTR加密: {encrypted_ctr[:50]}...")
    decrypted_ctr = encryptor.decrypt(encrypted_ctr)
    print(f"CTR解密: {decrypted_ctr}")
    print(f"CTR验证: {'成功' if decrypted_ctr == plaintext else '失败'}")

    print("\n" + "=" * 50)
    print("测试完成")
    print("=" * 50)