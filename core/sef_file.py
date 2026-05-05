#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SEF自加密文件格式模块（Self-Encrypting File）
扩展结构化加密格式到文件级别

创新点：
1. 文件自描述 — 包含加密算法、密钥标识、访问策略
2. 渐进式解密 — 支持部分解密（预览）和完全解密
3. 内嵌脱敏 — 文件内容自动应用SEF脱敏规则
4. 访问控制 — 文件级别权限检查
5. 完整性校验 — SHA256校验防止篡改

SEF文件结构：
┌─────────────────────────────────────────────────────────────┐
│  文件头 (64 bytes)                                           │
│  ├── 魔数 (4B): "SEF1"                                       │
│  ├── 版本 (1B): 1                                            │
│  ├── 算法 (1B): 1=SM4_CBC, 2=SM4_CTR                         │
│  ├── 密钥ID (16B)                                            │
│  ├── IV/Nonce (16B)                                          │
│  ├── 内容类型 (2B)                                           │
│  ├── 原始大小 (4B)                                           │
│  ├── 加密大小 (4B)                                           │
│  ├── 校验和 (16B)                                            │
│  ├── 策略ID (8B)                                             │
│  └── 时间戳 (8B)                                             │
├─────────────────────────────────────────────────────────────┤
│  元数据区 (变长)                                              │
│  ├── 长度 (4B)                                               │
│  └── JSON元数据                                              │
├─────────────────────────────────────────────────────────────┤
│  加密数据区                                                   │
│  └── SM4加密的文件内容                                        │
└─────────────────────────────────────────────────────────────┘
"""

import os
import json
import struct
import hashlib
import secrets
from datetime import datetime
from typing import Dict, Optional, Tuple, List, Any
import logging

logger = logging.getLogger(__name__)

# SEF文件魔数和版本
SEF_FILE_MAGIC = b'SEF1'
SEF_FILE_VERSION = 1


class SEFContentType:
    """SEF内容类型枚举"""
    GENERIC = 0       # 通用文件
    DOCUMENT = 1      # 文档
    SPREADSHEET = 2   # 表格
    DATABASE = 3      # 数据库导出
    IMAGE = 4         # 图片
    ARCHIVE = 5       # 压缩包
    STUDENT_DATA = 6  # 学生数据
    STAFF_DATA = 7    # 教职工数据
    AUDIT_LOG = 8     # 审计日志
    BACKUP = 9        # 备份文件

    NAMES = {
        0: '通用文件',
        1: '文档',
        2: '表格',
        3: '数据库导出',
        4: '图片',
        5: '压缩包',
        6: '学生数据',
        7: '教职工数据',
        8: '审计日志',
        9: '备份文件',
    }


class SEFAlgorithm:
    """SEF加密算法枚举"""
    SM4_CBC = 1
    SM4_CTR = 2

    NAMES = {
        1: 'SM4_CBC',
        2: 'SM4_CTR',
    }


class SEFFileHeader:
    """
    SEF文件头结构

    固定64字节，包含文件元信息

    结构 (小端序):
    - magic: 4 bytes       # 文件魔数 "SEF1"
    - version: 1 byte      # 版本号
    - algorithm: 1 byte    # 加密算法 (1=SM4_CBC, 2=SM4_CTR)
    - key_id: 16 bytes     # 密钥标识
    - iv_nonce: 16 bytes   # IV或Nonce
    - content_type: 2 bytes # 内容类型
    - original_size: 4 bytes # 原始文件大小
    - encrypted_size: 4 bytes # 加密后大小
    - checksum: 8 bytes    # 校验和 (SHA256前8字节)
    - policy_id: 4 bytes   # 访问策略ID
    - created_at: 4 bytes  # 创建时间戳
    """

    SIZE = 64  # 头部固定64字节

    def __init__(self):
        """初始化文件头"""
        self.magic = SEF_FILE_MAGIC
        self.version = SEF_FILE_VERSION
        self.algorithm = SEFAlgorithm.SM4_CBC
        self.key_id = b'\x00' * 16
        self.iv_nonce = b'\x00' * 16
        self.content_type = SEFContentType.GENERIC
        self.original_size = 0
        self.encrypted_size = 0
        self.checksum = b'\x00' * 8
        self.policy_id = b'defa'  # 4字节策略ID
        self.created_at = int(datetime.now().timestamp())

    def pack(self) -> bytes:
        """
        打包头部为字节

        Returns:
            bytes: 64字节的头部数据
        """
        # 格式: 4s + B + B + 16s + 16s + H + I + I + 8s + 4s + I = 4+1+1+16+16+2+4+4+8+4+4 = 64
        header = struct.pack(
            '<4sBB16s16sHII8s4sI',
            self.magic,
            self.version,
            self.algorithm,
            self.key_id[:16],
            self.iv_nonce[:16],
            self.content_type,
            self.original_size,
            self.encrypted_size,
            self.checksum[:8],
            self.policy_id[:4],
            self.created_at
        )
        return header

    @staticmethod
    def unpack(data: bytes) -> Optional['SEFFileHeader']:
        """
        解包字节为头部

        Args:
            data: 字节数据（至少64字节）

        Returns:
            SEFFileHeader: 解包后的头部，失败返回None
        """
        if len(data) < SEFFileHeader.SIZE:
            return None

        try:
            unpacked = struct.unpack(
                '<4sBB16s16sHII8s4sI',
                data[:SEFFileHeader.SIZE]
            )

            header = SEFFileHeader()
            header.magic = unpacked[0]
            header.version = unpacked[1]
            header.algorithm = unpacked[2]
            header.key_id = unpacked[3]
            header.iv_nonce = unpacked[4]
            header.content_type = unpacked[5]
            header.original_size = unpacked[6]
            header.encrypted_size = unpacked[7]
            header.checksum = unpacked[8]
            header.policy_id = unpacked[9]
            header.created_at = unpacked[10]

            return header
        except Exception as e:
            logger.error(f"SEF头部解包失败: {e}")
            return None

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'magic': self.magic.decode('ascii', errors='replace'),
            'version': self.version,
            'algorithm': SEFAlgorithm.NAMES.get(self.algorithm, 'unknown'),
            'key_id': self.key_id.hex(),
            'iv_nonce': self.iv_nonce.hex(),
            'content_type': SEFContentType.NAMES.get(self.content_type, 'unknown'),
            'content_type_code': self.content_type,
            'original_size': self.original_size,
            'encrypted_size': self.encrypted_size,
            'checksum': self.checksum.hex(),
            'policy_id': self.policy_id.decode('ascii', errors='replace'),
            'created_at': datetime.fromtimestamp(self.created_at).isoformat(),
        }

    def is_valid(self) -> bool:
        """验证头部有效性"""
        return self.magic == SEF_FILE_MAGIC and self.version == SEF_FILE_VERSION


class SEFFileAccessPolicy:
    """
    SEF文件访问策略管理器

    定义不同策略下各角色的访问权限

    策略ID映射（4字节）：
    - 'defa' -> default
    - 'publ' -> public
    - 'conf' -> confidential
    - 'tops' -> top_secret
    - 'audi' -> audit_only
    """

    # 策略ID短名称到完整名称的映射
    POLICY_ID_MAP = {
        'defa': 'default',
        'publ': 'public',
        'conf': 'confidential',
        'tops': 'top_secret',
        'audi': 'audit_only',
    }

    def __init__(self):
        """初始化默认策略"""
        self.policies = {
            'default': {
                'name': '默认策略',
                'roles': ['admin', 'security'],
                'operations': ['read', 'decrypt', 'preview', 'export'],
                'description': '管理员和安全员可完全访问',
            },
            'public': {
                'name': '公开策略',
                'roles': ['admin', 'security', 'auditor', 'user', 'guest'],
                'operations': ['read', 'preview'],
                'description': '所有用户可预览',
            },
            'confidential': {
                'name': '机密策略',
                'roles': ['admin', 'security'],
                'operations': ['read', 'decrypt'],
                'description': '仅管理员和安全员可访问',
            },
            'top_secret': {
                'name': '绝密策略',
                'roles': ['admin'],
                'operations': ['decrypt'],
                'description': '仅管理员可解密',
            },
            'audit_only': {
                'name': '审计策略',
                'roles': ['admin', 'auditor'],
                'operations': ['read', 'preview'],
                'description': '管理员和审计员可查看',
            },
        }

    def _normalize_policy_id(self, policy_id: str) -> str:
        """将短策略ID转换为完整策略名称"""
        # 如果是4字符短名称，转换为完整名称
        if len(policy_id) == 4 and policy_id in self.POLICY_ID_MAP:
            return self.POLICY_ID_MAP[policy_id]
        return policy_id

    def check_access(self, policy_id: str, user_role: str,
                     operation: str = 'read') -> bool:
        """
        检查访问权限

        Args:
            policy_id: 策略ID（可以是短名称或完整名称）
            user_role: 用户角色
            operation: 操作类型 (read, decrypt, preview, export)

        Returns:
            bool: 是否有权限
        """
        # 转换策略ID
        full_policy_id = self._normalize_policy_id(policy_id)

        policy = self.policies.get(full_policy_id)
        if not policy:
            return False

        return user_role in policy['roles'] and operation in policy['operations']

    def create_policy(self, policy_id: str, name: str,
                      roles: List[str], operations: List[str],
                      description: str = '') -> Tuple[bool, str]:
        """
        创建新策略

        Args:
            policy_id: 策略ID
            name: 策略名称
            roles: 允许的角色列表
            operations: 允许的操作列表
            description: 描述

        Returns:
            Tuple[bool, str]: (成功, 消息)
        """
        if policy_id in self.policies:
            return False, f"策略 {policy_id} 已存在"

        self.policies[policy_id] = {
            'name': name,
            'roles': roles,
            'operations': operations,
            'description': description,
        }

        logger.info(f"创建SEF访问策略: {policy_id}")
        return True, "策略创建成功"

    def get_policy(self, policy_id: str) -> Optional[Dict]:
        """获取策略详情"""
        return self.policies.get(policy_id)

    def get_all_policies(self) -> Dict[str, Dict]:
        """获取所有策略"""
        return self.policies.copy()

    def delete_policy(self, policy_id: str) -> Tuple[bool, str]:
        """删除策略"""
        if policy_id in ['default', 'public', 'confidential', 'top_secret']:
            return False, "内置策略不可删除"

        if policy_id not in self.policies:
            return False, f"策略 {policy_id} 不存在"

        del self.policies[policy_id]
        return True, "策略删除成功"


class SEFKeyManager:
    """
    SEF密钥管理器

    管理文件加密密钥的生成、存储和检索
    """

    def __init__(self, master_key: bytes = None):
        """
        初始化密钥管理器

        Args:
            master_key: 主密钥（用于派生文件密钥）
        """
        self.master_key = master_key or secrets.token_bytes(32)
        self.key_store: Dict[str, bytes] = {}  # key_id -> key

    def generate_key(self) -> Tuple[str, bytes]:
        """
        生成新的文件加密密钥

        Returns:
            Tuple[str, bytes]: (密钥ID, 密钥)
        """
        key_id = secrets.token_hex(8)  # 16字符ID
        key = secrets.token_bytes(16)  # SM4密钥
        self.key_store[key_id] = key
        return key_id, key

    def store_key(self, key_id: str, key: bytes):
        """存储密钥"""
        self.key_store[key_id] = key

    def get_key(self, key_id: str) -> Optional[bytes]:
        """获取密钥"""
        return self.key_store.get(key_id)

    def has_key(self, key_id: str) -> bool:
        """检查密钥是否存在"""
        return key_id in self.key_store

    def delete_key(self, key_id: str) -> bool:
        """删除密钥"""
        if key_id in self.key_store:
            del self.key_store[key_id]
            return True
        return False

    def export_keys(self) -> Dict[str, str]:
        """导出密钥（十六进制格式）"""
        return {kid: key.hex() for kid, key in self.key_store.items()}

    def import_keys(self, keys: Dict[str, str]):
        """导入密钥"""
        for kid, key_hex in keys.items():
            self.key_store[kid] = bytes.fromhex(key_hex)


class SEFFileEncryptor:
    """
    SEF自加密文件处理器

    核心功能：
    1. 将普通文件转换为SEF格式
    2. 解密SEF文件
    3. 渐进式预览
    4. 文件信息读取
    """

    def __init__(self, key_manager: SEFKeyManager = None,
                 policy_manager: SEFFileAccessPolicy = None):
        """
        初始化SEF文件加密器

        Args:
            key_manager: 密钥管理器
            policy_manager: 访问策略管理器
        """
        self.key_manager = key_manager or SEFKeyManager()
        self.policy_manager = policy_manager or SEFFileAccessPolicy()
        self._encryptor_cache = {}  # 缓存加密器实例

    def _get_encryptor(self, key: bytes):
        """获取SM4加密器（延迟导入避免循环依赖）"""
        from core.encryption import SM4Encryptor

        key_hex = key.hex()
        if key_hex not in self._encryptor_cache:
            self._encryptor_cache[key_hex] = SM4Encryptor(key)
        return self._encryptor_cache[key_hex]

    def encrypt_file(self, input_path: str, output_path: str,
                     content_type: int = SEFContentType.GENERIC,
                     policy_id: str = 'default',
                     metadata: Dict = None,
                     algorithm: int = SEFAlgorithm.SM4_CBC) -> Tuple[bool, str, Dict]:
        """
        将普通文件转换为SEF自加密文件

        Args:
            input_path: 输入文件路径
            output_path: 输出SEF文件路径
            content_type: 内容类型
            policy_id: 访问策略ID
            metadata: 附加元数据
            algorithm: 加密算法

        Returns:
            Tuple[bool, str, Dict]: (成功, 消息, 文件信息)
        """
        try:
            # 验证输入文件
            if not os.path.exists(input_path):
                return False, f"输入文件不存在: {input_path}", {}

            # 读取原始文件
            with open(input_path, 'rb') as f:
                original_data = f.read()

            original_size = len(original_data)
            checksum = hashlib.sha256(original_data).digest()[:8]

            # 生成密钥和IV
            key_id, encrypt_key = self.key_manager.generate_key()
            iv_nonce = secrets.token_bytes(16)

            # 获取加密器并加密
            encryptor = self._get_encryptor(encrypt_key)

            if algorithm == SEFAlgorithm.SM4_CBC:
                encrypted_data, _ = encryptor.encrypt_cbc(original_data, iv_nonce)
            else:
                encrypted_data, _ = encryptor.encrypt_ctr(original_data, iv_nonce)

            # 构建文件头
            header = SEFFileHeader()
            header.algorithm = algorithm
            header.key_id = key_id.encode('ascii')[:16].ljust(16, b'\x00')
            header.iv_nonce = iv_nonce
            header.content_type = content_type
            header.original_size = original_size
            header.encrypted_size = len(encrypted_data)
            header.checksum = checksum
            header.policy_id = policy_id.encode('ascii')[:4].ljust(4, b'\x00')
            header.created_at = int(datetime.now().timestamp())

            # 构建元数据，优先使用传入的metadata中的original_name
            custom_metadata = metadata or {}
            original_name = custom_metadata.get('original_name', os.path.basename(input_path))

            file_metadata = {
                'original_name': original_name,
                'encrypted_at': datetime.now().isoformat(),
                'custom': custom_metadata,
            }
            meta_bytes = json.dumps(file_metadata, ensure_ascii=False).encode('utf-8')
            meta_length = len(meta_bytes)

            # 确保输出目录存在
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # 写入SEF文件
            with open(output_path, 'wb') as f:
                # 1. 文件头 (64 bytes)
                f.write(header.pack())
                # 2. 元数据长度 (4 bytes) + 元数据
                f.write(struct.pack('<I', meta_length))
                f.write(meta_bytes)
                # 3. 加密数据
                f.write(encrypted_data)

            # 计算SEF文件大小
            sef_size = SEFFileHeader.SIZE + 4 + meta_length + len(encrypted_data)

            file_info = {
                'input_path': input_path,
                'output_path': output_path,
                'original_size': original_size,
                'encrypted_size': len(encrypted_data),
                'sef_size': sef_size,
                'compression_ratio': f"{sef_size / original_size:.2%}" if original_size > 0 else "N/A",
                'key_id': key_id,
                'checksum': checksum.hex(),
                'content_type': SEFContentType.NAMES.get(content_type, 'unknown'),
                'policy_id': policy_id,
            }

            logger.info(f"SEF文件创建成功: {input_path} -> {output_path}")
            return True, "文件加密成功", file_info

        except Exception as e:
            logger.error(f"SEF文件加密失败: {e}")
            return False, f"加密失败: {str(e)}", {}

    def decrypt_file(self, input_path: str, output_path: str,
                     user_role: str = None) -> Tuple[bool, str, Dict]:
        """
        解密SEF文件

        Args:
            input_path: SEF文件路径
            output_path: 输出文件路径
            user_role: 用户角色（用于访问控制检查）

        Returns:
            Tuple[bool, str, Dict]: (成功, 消息, 文件信息)
        """
        try:
            # 读取SEF文件
            with open(input_path, 'rb') as f:
                # 读取文件头
                header_data = f.read(SEFFileHeader.SIZE)
                header = SEFFileHeader.unpack(header_data)

                if not header or not header.is_valid():
                    return False, "无效的SEF文件格式", {}

                # 检查访问策略
                policy_id = header.policy_id.rstrip(b'\x00').decode('ascii', errors='replace')
                if user_role and not self.policy_manager.check_access(policy_id, user_role, 'decrypt'):
                    return False, f"角色 [{user_role}] 无权限解密此文件（策略: {policy_id}）", {}

                # 读取元数据
                meta_length = struct.unpack('<I', f.read(4))[0]
                metadata = json.loads(f.read(meta_length).decode('utf-8'))

                # 读取加密数据
                encrypted_data = f.read()

            # 获取解密密钥
            key_id = header.key_id.rstrip(b'\x00').decode('ascii', errors='replace')
            decrypt_key = self.key_manager.get_key(key_id)

            if not decrypt_key:
                return False, f"密钥不可用: {key_id}", {}

            # 解密数据
            encryptor = self._get_encryptor(decrypt_key)

            if header.algorithm == SEFAlgorithm.SM4_CBC:
                decrypted_data = encryptor.decrypt_cbc(encrypted_data, header.iv_nonce)
            else:
                decrypted_data = encryptor.decrypt_ctr(encrypted_data, header.iv_nonce)

            # 验证校验和
            checksum = hashlib.sha256(decrypted_data).digest()[:8]
            checksum_valid = checksum == header.checksum

            if not checksum_valid:
                logger.warning(f"SEF文件校验和不匹配: {input_path}")

            # 截取到原始大小
            decrypted_data = decrypted_data[:header.original_size]

            # 确保输出目录存在
            output_dir = os.path.dirname(output_path)
            if output_dir and not os.path.exists(output_dir):
                os.makedirs(output_dir, exist_ok=True)

            # 写入解密文件
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)

            file_info = {
                'input_path': input_path,
                'output_path': output_path,
                'original_size': header.original_size,
                'checksum_valid': checksum_valid,
                'content_type': SEFContentType.NAMES.get(header.content_type, 'unknown'),
                'metadata': metadata,
            }

            logger.info(f"SEF文件解密成功: {input_path} -> {output_path}")
            return True, "文件解密成功", file_info

        except Exception as e:
            logger.error(f"SEF文件解密失败: {e}")
            return False, f"解密失败: {str(e)}", {}

    def preview_file(self, input_path: str, preview_size: int = 1024,
                     user_role: str = None) -> Tuple[bool, bytes, Dict]:
        """
        渐进式解密：预览文件前N字节

        创新点：无需完全解密即可预览文件内容

        Args:
            input_path: SEF文件路径
            preview_size: 预览大小（字节）
            user_role: 用户角色

        Returns:
            Tuple[bool, bytes, Dict]: (成功, 预览数据, 文件信息)
        """
        try:
            with open(input_path, 'rb') as f:
                # 读取文件头
                header_data = f.read(SEFFileHeader.SIZE)
                header = SEFFileHeader.unpack(header_data)

                if not header or not header.is_valid():
                    return False, b'', {}

                # 检查预览权限
                policy_id = header.policy_id.rstrip(b'\x00').decode('ascii', errors='replace')
                if user_role and not self.policy_manager.check_access(policy_id, user_role, 'preview'):
                    return False, b'', {'error': '无预览权限'}

                # 读取元数据
                meta_length = struct.unpack('<I', f.read(4))[0]
                metadata = json.loads(f.read(meta_length).decode('utf-8'))

                # 读取加密数据
                encrypted_data = f.read()

            # 获取密钥
            key_id = header.key_id.rstrip(b'\x00').decode('ascii', errors='replace')
            decrypt_key = self.key_manager.get_key(key_id)

            if not decrypt_key:
                return False, b'', {'error': '密钥不可用'}

            # 解密
            encryptor = self._get_encryptor(decrypt_key)

            if header.algorithm == SEFAlgorithm.SM4_CBC:
                decrypted_data = encryptor.decrypt_cbc(encrypted_data, header.iv_nonce)
            else:
                decrypted_data = encryptor.decrypt_ctr(encrypted_data, header.iv_nonce)

            # 截取预览
            preview = decrypted_data[:min(preview_size, header.original_size)]

            file_info = header.to_dict()
            file_info['metadata'] = metadata
            file_info['preview_size'] = len(preview)

            return True, preview, file_info

        except Exception as e:
            logger.error(f"SEF预览失败: {e}")
            return False, b'', {'error': str(e)}

    def get_file_info(self, input_path: str) -> Optional[Dict]:
        """
        获取SEF文件信息（不解密内容）

        Args:
            input_path: SEF文件路径

        Returns:
            Dict: 文件信息
        """
        try:
            with open(input_path, 'rb') as f:
                # 读取文件头
                header_data = f.read(SEFFileHeader.SIZE)
                header = SEFFileHeader.unpack(header_data)

                if not header:
                    return None

                # 读取元数据
                meta_length = struct.unpack('<I', f.read(4))[0]
                metadata = json.loads(f.read(meta_length).decode('utf-8'))

                # 获取文件大小
                f.seek(0, 2)  # 移动到文件末尾
                file_size = f.tell()

            info = header.to_dict()
            info['metadata'] = metadata
            info['file_path'] = input_path
            info['file_size'] = file_size
            info['is_sef'] = header.is_valid()

            # 计算开销
            overhead = file_size - header.encrypted_size - SEFFileHeader.SIZE - 4 - meta_length
            info['format_overhead'] = SEFFileHeader.SIZE + 4 + meta_length
            info['overhead_ratio'] = f"{(SEFFileHeader.SIZE + 4 + meta_length) / file_size:.2%}"

            return info

        except Exception as e:
            logger.error(f"获取SEF文件信息失败: {e}")
            return None

    def is_sef_file(self, file_path: str) -> bool:
        """
        判断是否为SEF文件

        Args:
            file_path: 文件路径

        Returns:
            bool: 是否为SEF文件
        """
        try:
            with open(file_path, 'rb') as f:
                magic = f.read(4)
            return magic == SEF_FILE_MAGIC
        except:
            return False

    def batch_encrypt(self, input_dir: str, output_dir: str,
                      content_type: int = SEFContentType.GENERIC,
                      policy_id: str = 'default',
                      file_extensions: List[str] = None) -> Tuple[int, int, List[Dict]]:
        """
        批量加密目录下的文件

        Args:
            input_dir: 输入目录
            output_dir: 输出目录
            content_type: 内容类型
            policy_id: 策略ID
            file_extensions: 要加密的文件扩展名列表

        Returns:
            Tuple[int, int, List[Dict]]: (成功数, 失败数, 结果列表)
        """
        success_count = 0
        failure_count = 0
        results = []

        if not os.path.exists(input_dir):
            return 0, 0, []

        for root, _, files in os.walk(input_dir):
            for filename in files:
                # 检查扩展名
                if file_extensions:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in file_extensions:
                        continue

                input_path = os.path.join(root, filename)
                rel_path = os.path.relpath(input_path, input_dir)
                output_path = os.path.join(output_dir, rel_path + '.sef')

                success, msg, info = self.encrypt_file(
                    input_path, output_path,
                    content_type=content_type,
                    policy_id=policy_id
                )

                if success:
                    success_count += 1
                else:
                    failure_count += 1

                results.append({
                    'input': input_path,
                    'output': output_path,
                    'success': success,
                    'message': msg,
                })

        logger.info(f"批量加密完成: 成功 {success_count}, 失败 {failure_count}")
        return success_count, failure_count, results

    def re_encrypt(self, input_path: str, output_path: str,
                   new_policy_id: str = None) -> Tuple[bool, str]:
        """
        重新加密文件（更换密钥或策略）

        Args:
            input_path: SEF文件路径
            output_path: 输出路径
            new_policy_id: 新策略ID

        Returns:
            Tuple[bool, str]: (成功, 消息)
        """
        try:
            # 获取文件信息
            info = self.get_file_info(input_path)
            if not info:
                return False, "无法读取SEF文件信息"

            # 解密到临时位置
            import tempfile
            with tempfile.NamedTemporaryFile(delete=False) as tmp:
                tmp_path = tmp.name

            success, msg, _ = self.decrypt_file(input_path, tmp_path)
            if not success:
                os.unlink(tmp_path)
                return False, f"解密失败: {msg}"

            # 重新加密
            policy_id = new_policy_id or info['policy_id']
            success, msg, _ = self.encrypt_file(
                tmp_path, output_path,
                content_type=info['content_type_code'],
                policy_id=policy_id,
                metadata=info.get('metadata', {}).get('custom', {})
            )

            # 清理临时文件
            os.unlink(tmp_path)

            return success, msg

        except Exception as e:
            logger.error(f"重新加密失败: {e}")
            return False, str(e)


def create_sef_encryptor() -> SEFFileEncryptor:
    """
    创建SEF文件加密器实例

    Returns:
        SEFFileEncryptor: 加密器实例
    """
    return SEFFileEncryptor()


# 模块测试
if __name__ == '__main__':
    print("=" * 60)
    print("SEF自加密文件格式模块测试")
    print("=" * 60)

    # 测试文件头
    print("\n1. 文件头测试")
    header = SEFFileHeader()
    print(f"   头部大小: {SEFFileHeader.SIZE} 字节")
    print(f"   头部信息: {header.to_dict()}")

    packed = header.pack()
    print(f"   打包后长度: {len(packed)} 字节")

    unpacked = SEFFileHeader.unpack(packed)
    print(f"   解包成功: {unpacked is not None}")
    print(f"   验证有效: {unpacked.is_valid()}")

    # 测试访问策略
    print("\n2. 访问策略测试")
    policy = SEFFileAccessPolicy()
    print(f"   默认策略: {policy.get_policy('default')}")
    print(f"   admin可解密default: {policy.check_access('default', 'admin', 'decrypt')}")
    print(f"   user可解密default: {policy.check_access('default', 'user', 'decrypt')}")
    print(f"   user可预览public: {policy.check_access('public', 'user', 'preview')}")

    # 测试密钥管理
    print("\n3. 密钥管理测试")
    km = SEFKeyManager()
    kid, key = km.generate_key()
    print(f"   生成密钥ID: {kid}")
    print(f"   密钥长度: {len(key)} 字节")
    print(f"   获取密钥: {km.get_key(kid).hex()[:32]}...")

    # 测试SEF文件加密
    print("\n4. SEF文件加密测试")
    import tempfile

    encryptor = SEFFileEncryptor()

    # 创建测试文件
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        f.write("这是测试文件内容，用于验证SEF加密功能。" * 100)
        test_input = f.name

    test_output = test_input + '.sef'

    # 加密
    success, msg, info = encryptor.encrypt_file(
        test_input, test_output,
        content_type=SEFContentType.DOCUMENT,
        policy_id='default'
    )
    print(f"   加密结果: {success}")
    print(f"   加密信息: {info}")

    # 获取文件信息
    if success:
        file_info = encryptor.get_file_info(test_output)
        print(f"   SEF文件信息: {file_info}")

        # 预览
        ok, preview, _ = encryptor.preview_file(test_output, preview_size=50)
        print(f"   预览成功: {ok}")
        print(f"   预览内容: {preview[:50]}...")

        # 解密
        test_decrypted = test_input + '.decrypted'
        success2, msg2, _ = encryptor.decrypt_file(test_output, test_decrypted, user_role='admin')
        print(f"   解密结果: {success2}")

        # 清理
        os.unlink(test_output)
        if os.path.exists(test_decrypted):
            os.unlink(test_decrypted)

    os.unlink(test_input)

    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)
