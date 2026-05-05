#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
SEF文件API路由
提供SEF文件加密、解密、预览等功能的RESTful API
"""

import os
import tempfile
import uuid
from datetime import datetime
from flask import Blueprint, request, jsonify, send_file, current_app
from flask_login import login_required, current_user
import logging

logger = logging.getLogger(__name__)

sef_api = Blueprint('sef_api', __name__)

# 全局SEF加密器实例
_sef_encryptor = None


def get_sef_encryptor():
    """获取SEF加密器实例"""
    global _sef_encryptor
    if _sef_encryptor is None:
        from core.sef_file import SEFFileEncryptor, SEFKeyManager, SEFFileAccessPolicy

        # 尝试从应用配置获取主密钥
        master_key = current_app.config.get('SEF_MASTER_KEY')
        key_manager = SEFKeyManager(master_key)
        policy_manager = SEFFileAccessPolicy()

        _sef_encryptor = SEFFileEncryptor(key_manager, policy_manager)
    return _sef_encryptor


@sef_api.route('/encrypt', methods=['POST'])
def encrypt_file():
    """
    加密文件为SEF格式

    请求参数:
        file: 上传的文件
        content_type: 内容类型 (0-9)
        policy_id: 访问策略ID
        algorithm: 加密算法 (1=SM4_CBC, 2=SM4_CTR)

    返回:
        success: 是否成功
        info: 文件信息
        download_url: 下载链接
    """
    try:
        logger.info("SEF加密请求开始处理")

        # 检查文件
        if 'file' not in request.files:
            logger.warning("未上传文件")
            return jsonify({'success': False, 'error': '未上传文件'}), 400

        file = request.files['file']
        if file.filename == '':
            logger.warning("文件名为空")
            return jsonify({'success': False, 'error': '文件名为空'}), 400

        original_filename = file.filename
        logger.info(f"接收到文件: {original_filename}")

        # 获取参数
        content_type = int(request.form.get('content_type', 0))
        policy_id = request.form.get('policy_id', 'default')
        algorithm = int(request.form.get('algorithm', 1))

        logger.info(f"参数: content_type={content_type}, policy_id={policy_id}, algorithm={algorithm}")

        # 创建临时目录
        temp_dir = tempfile.gettempdir()
        input_path = os.path.join(temp_dir, f"sef_input_{uuid.uuid4().hex}")
        output_path = os.path.join(temp_dir, f"sef_output_{uuid.uuid4().hex}.sef")

        # 保存上传文件
        file.save(input_path)
        logger.info(f"文件已保存到: {input_path}")

        # 加密
        encryptor = get_sef_encryptor()
        logger.info("获取加密器成功")

        # 传递原始文件名作为元数据
        metadata = {'original_name': original_filename}

        success, msg, info = encryptor.encrypt_file(
            input_path, output_path,
            content_type=content_type,
            policy_id=policy_id,
            algorithm=algorithm,
            metadata=metadata
        )
        logger.info(f"加密结果: success={success}, msg={msg}")

        # 清理输入文件
        if os.path.exists(input_path):
            os.unlink(input_path)

        if success:
            # 记录审计日志
            try:
                from core.audit import AuditLogger
                audit = AuditLogger()
                audit.log_action(
                    user_id=getattr(current_user, 'id', 0) if current_user.is_authenticated else 0,
                    username=getattr(current_user, 'username', 'anonymous') if current_user.is_authenticated else 'anonymous',
                    action='sef_encrypt',
                    resource='sef_file',
                    ip_address=request.remote_addr,
                    details=f"加密文件: {original_filename}, 策略: {policy_id}"
                )
            except:
                pass

            # 生成下载URL
            download_url = f"/api/sef/download/{os.path.basename(output_path)}"

            return jsonify({
                'success': True,
                'message': msg,
                'info': info,
                'download_url': download_url,
                'temp_file': output_path
            })
        else:
            return jsonify({'success': False, 'error': msg}), 400

    except Exception as e:
        logger.exception(f"SEF加密失败: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/decrypt', methods=['POST'])
def decrypt_file():
    """
    解密SEF文件

    请求参数:
        sef_file: 上传的SEF文件
        user_role: 用户角色

    返回:
        success: 是否成功
        info: 文件信息
        download_url: 下载链接
        original_name: 原始文件名
    """
    try:
        # 检查文件
        if 'sef_file' not in request.files:
            return jsonify({'success': False, 'error': '未上传SEF文件'}), 400

        file = request.files['sef_file']
        if file.filename == '':
            return jsonify({'success': False, 'error': '文件名为空'}), 400

        # 获取角色
        user_role = request.form.get('user_role', 'admin')

        # 创建临时目录
        temp_dir = tempfile.gettempdir()
        input_path = os.path.join(temp_dir, f"sef_decrypt_input_{uuid.uuid4().hex}")
        output_path = os.path.join(temp_dir, f"sef_decrypt_output_{uuid.uuid4().hex}")

        # 保存上传文件
        file.save(input_path)

        # 解密
        encryptor = get_sef_encryptor()
        success, msg, info = encryptor.decrypt_file(input_path, output_path, user_role)

        # 清理输入文件
        if os.path.exists(input_path):
            os.unlink(input_path)

        if success:
            # 记录审计日志
            try:
                from core.audit import AuditLogger
                audit = AuditLogger()
                audit.log_action(
                    user_id=getattr(current_user, 'id', 0) if current_user.is_authenticated else 0,
                    username=getattr(current_user, 'username', 'anonymous') if current_user.is_authenticated else 'anonymous',
                    action='sef_decrypt',
                    resource='sef_file',
                    ip_address=request.remote_addr,
                    details=f"解密文件, 角色: {user_role}, 校验: {info.get('checksum_valid', False)}"
                )
            except:
                pass

            # 获取原始文件名（从元数据中提取）
            metadata = info.get('metadata', {})
            original_name = metadata.get('original_name', '')
            logger.info(f"解密元数据: {metadata}")
            logger.info(f"原始文件名: {original_name}")

            if not original_name or original_name == 'unknown':
                original_name = 'decrypted_file'

            # 生成下载URL，包含原始文件名作为查询参数
            download_url = f"/api/sef/download/{os.path.basename(output_path)}?name={original_name}"

            return jsonify({
                'success': True,
                'message': msg,
                'info': info,
                'download_url': download_url,
                'original_name': original_name,
                'temp_file': output_path
            })
        else:
            return jsonify({'success': False, 'error': msg}), 403

    except Exception as e:
        logger.error(f"SEF解密失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/preview', methods=['POST'])
def preview_file():
    """
    预览SEF文件内容

    请求参数:
        preview_file: 上传的SEF文件
        preview_size: 预览大小（字节）

    返回:
        success: 是否成功
        preview: 预览内容
        info: 文件信息
    """
    try:
        # 检查文件
        if 'preview_file' not in request.files:
            return jsonify({'success': False, 'error': '未上传SEF文件'}), 400

        file = request.files['preview_file']

        # 获取预览大小
        preview_size = int(request.form.get('preview_size', 256))

        # 创建临时目录
        temp_dir = tempfile.gettempdir()
        input_path = os.path.join(temp_dir, f"sef_preview_{uuid.uuid4().hex}")

        # 保存上传文件
        file.save(input_path)

        # 获取用户角色
        user_role = 'admin'  # 演示模式默认管理员角色

        # 预览
        encryptor = get_sef_encryptor()
        success, preview, info = encryptor.preview_file(input_path, preview_size, user_role)

        # 清理
        if os.path.exists(input_path):
            os.unlink(input_path)

        if success:
            # 获取原始文件名和扩展名
            metadata = info.get('metadata', {})
            original_name = metadata.get('original_name', '')
            file_ext = ''
            if original_name:
                file_ext = original_name.rsplit('.', 1)[-1].lower() if '.' in original_name else ''

            # 根据文件类型智能显示预览
            preview_text = ''
            preview_type = 'binary'
            image_base64 = None

            # 图片文件 - 返回Base64用于前端显示
            image_exts = ['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico']
            if file_ext in image_exts:
                preview_type = 'image'
                import base64
                image_base64 = base64.b64encode(preview).decode('ascii')
                # 构建可显示的预览信息
                preview_text = f"📷 图片文件: {original_name}\n"
                preview_text += f"文件类型: {file_ext.upper()}\n"
                preview_text += f"预览大小: {len(preview)} 字节\n"
                preview_text += f"提示: 图片预览显示在下方"
            # 文本文件 - 直接解码
            elif file_ext in ['txt', 'csv', 'json', 'xml', 'html', 'css', 'js', 'py', 'md', 'log']:
                preview_type = 'text'
                preview_text = preview.decode('utf-8', errors='replace')
            # 二进制文件 - 显示十六进制和文件头信息
            else:
                preview_type = 'binary'
                # 尝试识别常见文件格式
                magic_header = preview[:8] if len(preview) >= 8 else preview
                file_signature = ''

                if magic_header[:4] == b'\x89PNG':
                    file_signature = 'PNG 图片'
                    preview_type = 'image'
                    import base64
                    image_base64 = base64.b64encode(preview).decode('ascii')
                elif magic_header[:2] == b'\xff\xd8':
                    file_signature = 'JPEG 图片'
                    preview_type = 'image'
                    import base64
                    image_base64 = base64.b64encode(preview).decode('ascii')
                elif magic_header[:4] == b'GIF8':
                    file_signature = 'GIF 图片'
                    preview_type = 'image'
                    import base64
                    image_base64 = base64.b64encode(preview).decode('ascii')
                elif magic_header[:2] == b'BM':
                    file_signature = 'BMP 图片'
                elif magic_header[:4] == b'PK\x03\x04':
                    file_signature = 'ZIP/PKZIP 压缩文件'
                elif magic_header[:4] == b'Rar!':
                    file_signature = 'RAR 压缩文件'
                elif magic_header[:4] == b'%PDF':
                    file_signature = 'PDF 文档'
                else:
                    file_signature = '未知格式'

                if preview_type == 'image':
                    preview_text = f"📷 图片文件: {original_name or '未知'}\n"
                    preview_text += f"识别格式: {file_signature}\n"
                    preview_text += f"预览大小: {len(preview)} 字节\n"
                    preview_text += f"提示: 图片预览显示在下方"
                else:
                    preview_text = f"📦 二进制文件: {original_name or '未知'}\n"
                    preview_text += f"识别格式: {file_signature}\n"
                    preview_text += f"预览大小: {len(preview)} 字节\n\n"
                    preview_text += f"十六进制预览:\n{preview[:100].hex()}\n"

            return jsonify({
                'success': True,
                'preview': preview_text,
                'preview_type': preview_type,
                'preview_bytes': len(preview),
                'original_name': original_name,
                'file_ext': file_ext,
                'image_base64': image_base64,
                'info': info
            })
        else:
            return jsonify({'success': False, 'error': info.get('error', '预览失败')}), 403

    except Exception as e:
        logger.error(f"SEF预览失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/info', methods=['POST'])
def get_file_info():
    """
    获取SEF文件信息

    请求参数:
        info_file: 上传的SEF文件

    返回:
        success: 是否成功
        info: 文件信息
    """
    try:
        # 检查文件
        if 'info_file' not in request.files:
            return jsonify({'success': False, 'error': '未上传SEF文件'}), 400

        file = request.files['info_file']

        # 创建临时目录
        temp_dir = tempfile.gettempdir()
        input_path = os.path.join(temp_dir, f"sef_info_{uuid.uuid4().hex}")

        # 保存上传文件
        file.save(input_path)

        # 获取信息
        encryptor = get_sef_encryptor()
        info = encryptor.get_file_info(input_path)

        # 清理
        if os.path.exists(input_path):
            os.unlink(input_path)

        if info:
            return jsonify({
                'success': True,
                'info': info
            })
        else:
            return jsonify({'success': False, 'error': '无法读取文件信息'}), 400

    except Exception as e:
        logger.error(f"获取SEF文件信息失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/download/<filename>', methods=['GET'])
@login_required
def download_file(filename):
    """
    下载临时文件

    Args:
        filename: 临时文件名
    """
    try:
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, filename)

        if not os.path.exists(file_path):
            return jsonify({'success': False, 'error': '文件不存在或已过期'}), 404

        # 获取原始文件名（从查询参数）
        original_name = request.args.get('name', '')

        # 确定下载文件名
        if filename.endswith('.sef'):
            download_name = f"encrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sef"
        else:
            # 使用原始文件名，如果没有则使用默认名
            if original_name:
                download_name = original_name
            else:
                download_name = f"decrypted_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bin"

        return send_file(
            file_path,
            as_attachment=True,
            download_name=download_name
        )

    except Exception as e:
        logger.error(f"文件下载失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/policies', methods=['GET'])
@login_required
def get_policies():
    """
    获取所有访问策略

    返回:
        policies: 策略列表
    """
    try:
        encryptor = get_sef_encryptor()
        policies = encryptor.policy_manager.get_all_policies()

        return jsonify({
            'success': True,
            'policies': policies
        })

    except Exception as e:
        logger.error(f"获取策略失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/check-access', methods=['POST'])
@login_required
def check_access():
    """
    检查访问权限

    请求参数:
        policy_id: 策略ID
        user_role: 用户角色
        operation: 操作类型

    返回:
        allowed: 是否允许
    """
    try:
        policy_id = request.json.get('policy_id', 'default')
        user_role = request.json.get('user_role', 'user')
        operation = request.json.get('operation', 'read')

        encryptor = get_sef_encryptor()
        allowed = encryptor.policy_manager.check_access(policy_id, user_role, operation)

        return jsonify({
            'success': True,
            'allowed': allowed,
            'policy_id': policy_id,
            'user_role': user_role,
            'operation': operation
        })

    except Exception as e:
        logger.error(f"权限检查失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@sef_api.route('/content-types', methods=['GET'])
@login_required
def get_content_types():
    """
    获取所有内容类型

    返回:
        content_types: 内容类型列表
    """
    from core.sef_file import SEFContentType

    return jsonify({
        'success': True,
        'content_types': SEFContentType.NAMES
    })


@sef_api.route('/algorithms', methods=['GET'])
@login_required
def get_algorithms():
    """
    获取所有加密算法

    返回:
        algorithms: 算法列表
    """
    from core.sef_file import SEFAlgorithm

    return jsonify({
        'success': True,
        'algorithms': SEFAlgorithm.NAMES
    })


@sef_api.route('/is-sef', methods=['POST'])
@login_required
def is_sef_file():
    """
    检查文件是否为SEF格式

    请求参数:
        file: 上传的文件

    返回:
        is_sef: 是否为SEF文件
    """
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': '未上传文件'}), 400

        file = request.files['file']

        # 读取前4字节
        magic = file.read(4)
        file.seek(0)

        is_sef = magic == b'SEF1'

        return jsonify({
            'success': True,
            'is_sef': is_sef,
            'filename': file.filename
        })

    except Exception as e:
        logger.error(f"SEF检查失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


# 注册蓝图函数
def register_sef_api(app):
    """
    注册SEF API蓝图到Flask应用

    Args:
        app: Flask应用实例
    """
    app.register_blueprint(sef_api, url_prefix='/api/sef')
    logger.info("SEF API注册完成")
