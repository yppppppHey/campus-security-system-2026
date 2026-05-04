#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
安全审计日志模块
实现全链路安全审计日志记录

功能:
    - 用户操作日志
    - 登录日志
    - 数据访问日志
    - 安全事件日志
    - 日志分析和告警
"""

import os
import json
import time
import uuid
import hashlib
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Union,Tuple
from dataclasses import dataclass, asdict
from enum import IntEnum
import logging
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class RiskLevel(IntEnum):
    """风险级别"""
    LOW = 1       # 低风险：正常操作
    MEDIUM = 2    # 中风险：敏感操作
    HIGH = 3      # 高风险：危险操作
    CRITICAL = 4  # 极高风险：安全事件


class AuditEventType(IntEnum):
    """审计事件类型"""
    # 认证事件
    LOGIN_SUCCESS = 1001
    LOGIN_FAILURE = 1002
    LOGOUT = 1003
    PASSWORD_CHANGE = 1004
    PASSWORD_RESET = 1005
    SESSION_EXPIRED = 1006

    # 用户管理
    USER_CREATE = 2001
    USER_UPDATE = 2002
    USER_DELETE = 2003
    USER_ENABLE = 2004
    USER_DISABLE = 2005

    # 权限管理
    ROLE_CREATE = 3001
    ROLE_UPDATE = 3002
    ROLE_DELETE = 3003
    PERMISSION_GRANT = 3004
    PERMISSION_REVOKE = 3005

    # 数据操作
    DATA_CREATE = 4001
    DATA_READ = 4002
    DATA_UPDATE = 4003
    DATA_DELETE = 4004
    DATA_EXPORT = 4005
    DATA_IMPORT = 4006

    # 敏感数据
    SENSITIVE_VIEW = 5001
    SENSITIVE_DECRYPT = 5002
    SENSITIVE_MASK = 5003

    # 加密操作
    FILE_ENCRYPT = 6001
    FILE_DECRYPT = 6002
    KEY_GENERATE = 6003

    # 系统操作
    SYSTEM_CONFIG = 7001
    SYSTEM_BACKUP = 7002
    SYSTEM_RESTORE = 7003

    # 安全事件
    PERMISSION_DENIED = 8001
    BRUTE_FORCE = 8002
    SQL_INJECTION = 8003
    XSS_ATTACK = 8004
    ABNORMAL_ACCESS = 8005


@dataclass
class AuditLog:
    """审计日志数据类"""
    id: str
    timestamp: str
    event_type: int
    event_name: str
    user_id: Optional[int]
    username: str
    ip_address: str
    user_agent: str
    resource: str
    resource_id: Optional[str]
    action: str
    method: str
    request_url: str
    request_data: Optional[str]
    response_code: int
    response_msg: str
    risk_level: int
    details: Optional[str]
    session_id: str
    trace_id: str


class AuditLogger:
    """
    审计日志记录器
    提供完整的审计日志功能
    """

    # 事件名称映射
    EVENT_NAMES = {
        AuditEventType.LOGIN_SUCCESS: '登录成功',
        AuditEventType.LOGIN_FAILURE: '登录失败',
        AuditEventType.LOGOUT: '登出',
        AuditEventType.PASSWORD_CHANGE: '密码修改',
        AuditEventType.PASSWORD_RESET: '密码重置',
        AuditEventType.USER_CREATE: '创建用户',
        AuditEventType.USER_UPDATE: '更新用户',
        AuditEventType.USER_DELETE: '删除用户',
        AuditEventType.ROLE_CREATE: '创建角色',
        AuditEventType.ROLE_UPDATE: '更新角色',
        AuditEventType.ROLE_DELETE: '删除角色',
        AuditEventType.DATA_CREATE: '创建数据',
        AuditEventType.DATA_READ: '读取数据',
        AuditEventType.DATA_UPDATE: '更新数据',
        AuditEventType.DATA_DELETE: '删除数据',
        AuditEventType.DATA_EXPORT: '导出数据',
        AuditEventType.SENSITIVE_VIEW: '查看敏感数据',
        AuditEventType.SENSITIVE_DECRYPT: '解密敏感数据',
        AuditEventType.FILE_ENCRYPT: '文件加密',
        AuditEventType.FILE_DECRYPT: '文件解密',
        AuditEventType.PERMISSION_DENIED: '权限拒绝',
        AuditEventType.ABNORMAL_ACCESS: '异常访问',
    }

    # 高风险事件
    HIGH_RISK_EVENTS = {
        AuditEventType.LOGIN_FAILURE,
        AuditEventType.USER_DELETE,
        AuditEventType.ROLE_DELETE,
        AuditEventType.SENSITIVE_DECRYPT,
        AuditEventType.FILE_DECRYPT,
        AuditEventType.PERMISSION_DENIED,
        AuditEventType.BRUTE_FORCE,
        AuditEventType.SQL_INJECTION,
        AuditEventType.XSS_ATTACK,
    }

    def __init__(self, log_file: str = None, max_size: int = 50 * 1024 * 1024,
                 backup_count: int = 10):
        """
        初始化审计日志记录器

        Args:
            log_file: 日志文件路径
            max_size: 单个日志文件最大大小
            backup_count: 备份文件数量
        """
        self.log_file = log_file or 'logs/audit.log'
        self.max_size = max_size
        self.backup_count = backup_count

        # 确保日志目录存在
        log_dir = os.path.dirname(self.log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)

        # 初始化文件处理器
        self.file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=max_size,
            backupCount=backup_count,
            encoding='utf-8'
        )
        self.file_handler.setFormatter(logging.Formatter(
            '%(message)s'
        ))

        # 专用日志器
        self.logger = logging.getLogger('audit')
        self.logger.setLevel(logging.INFO)
        self.logger.addHandler(self.file_handler)
        self.logger.propagate = False

        # 内存缓存（用于实时分析）
        self._log_cache: List[AuditLog] = []
        self._cache_lock = threading.Lock()
        self._cache_size = 1000

        # 异步写入线程池
        self._executor = ThreadPoolExecutor(max_workers=2)

        logger.info(f"审计日志记录器初始化完成: {self.log_file}")

    def _generate_id(self) -> str:
        """生成唯一ID"""
        return uuid.uuid4().hex

    def _generate_trace_id(self) -> str:
        """生成追踪ID"""
        return uuid.uuid4().hex[:16]

    def _get_timestamp(self) -> str:
        """获取ISO格式时间戳"""
        return datetime.now().isoformat()

    def _determine_risk_level(self, event_type: AuditEventType,
                              success: bool = True) -> int:
        """
        确定风险级别

        Args:
            event_type: 事件类型
            success: 操作是否成功

        Returns:
            int: 风险级别
        """
        if event_type in self.HIGH_RISK_EVENTS:
            return RiskLevel.HIGH if success else RiskLevel.CRITICAL

        # 根据事件类型判断
        if event_type in [AuditEventType.USER_DELETE, AuditEventType.ROLE_DELETE]:
            return RiskLevel.HIGH
        elif event_type in [AuditEventType.SENSITIVE_DECRYPT, AuditEventType.FILE_DECRYPT]:
            return RiskLevel.HIGH
        elif event_type in [AuditEventType.USER_CREATE, AuditEventType.ROLE_CREATE,
                           AuditEventType.PASSWORD_CHANGE]:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW

    def log(self, log_entry: AuditLog):
        """
        记录审计日志

        Args:
            log_entry: 日志条目
        """
        # 写入文件
        log_json = json.dumps(asdict(log_entry), ensure_ascii=False)
        self.logger.info(log_json)

        # 添加到缓存
        with self._cache_lock:
            self._log_cache.append(log_entry)
            if len(self._log_cache) > self._cache_size:
                self._log_cache = self._log_cache[-self._cache_size:]

    def log_action(self, user_id: int = None, username: str = None,
                   action: str = None, resource: str = None,
                   resource_id: str = None, method: str = None,
                   ip_address: str = None, user_agent: str = None,
                   request_url: str = None, request_data: str = None,
                   response_code: int = 200, response_msg: str = None,
                   risk_level: int = None, details: str = None,
                   session_id: str = None, event_type: int = None):
        """
        记录操作日志

        Args:
            user_id: 用户ID
            username: 用户名
            action: 操作
            resource: 资源
            resource_id: 资源ID
            method: HTTP方法
            ip_address: IP地址
            user_agent: 用户代理
            request_url: 请求URL
            request_data: 请求数据
            response_code: 响应码
            response_msg: 响应消息
            risk_level: 风险级别
            details: 详细信息
            session_id: 会话ID
            event_type: 事件类型
        """
        # 确定事件类型
        if event_type is None:
            event_type = AuditEventType.DATA_READ

        # 确定风险级别
        if risk_level is None:
            risk_level = self._determine_risk_level(AuditEventType(event_type))

        log_entry = AuditLog(
            id=self._generate_id(),
            timestamp=self._get_timestamp(),
            event_type=event_type,
            event_name=self.EVENT_NAMES.get(AuditEventType(event_type), action),
            user_id=user_id,
            username=username or 'anonymous',
            ip_address=ip_address or '0.0.0.0',
            user_agent=user_agent or '',
            resource=resource or '',
            resource_id=resource_id,
            action=action or '',
            method=method or '',
            request_url=request_url or '',
            request_data=request_data,
            response_code=response_code,
            response_msg=response_msg or '',
            risk_level=risk_level,
            details=details,
            session_id=session_id or '',
            trace_id=self._generate_trace_id()
        )

        self.log(log_entry)

        # 高风险操作告警
        if risk_level >= RiskLevel.HIGH:
            self._alert_high_risk(log_entry)

    def log_login_attempt(self, user_id: int = None, username: str = None,
                          success: bool = True, ip_address: str = None,
                          user_agent: str = None, failure_reason: str = None):
        """
        记录登录日志

        Args:
            user_id: 用户ID
            username: 用户名
            success: 是否成功
            ip_address: IP地址
            user_agent: 用户代理
            failure_reason: 失败原因
        """
        event_type = AuditEventType.LOGIN_SUCCESS if success else AuditEventType.LOGIN_FAILURE

        self.log_action(
            user_id=user_id,
            username=username,
            action='login' if success else 'login_failed',
            resource='auth',
            method='POST',
            ip_address=ip_address,
            user_agent=user_agent,
            request_url='/auth/login',
            response_code=200 if success else 401,
            response_msg=failure_reason or ('登录成功' if success else '登录失败'),
            risk_level=RiskLevel.LOW if success else RiskLevel.MEDIUM,
            details=json.dumps({'failure_reason': failure_reason}) if failure_reason else None,
            event_type=event_type
        )

        # 记录到数据库
        self._record_login_to_db(user_id, username, success, ip_address, user_agent, failure_reason)

    def log_data_access(self, user_id: int, username: str,
                        data_type: str, data_id: int,
                        access_type: str, ip_address: str,
                        query_condition: str = None, result_count: int = 0):
        """
        记录数据访问日志

        Args:
            user_id: 用户ID
            username: 用户名
            data_type: 数据类型
            data_id: 数据ID
            access_type: 访问类型
            ip_address: IP地址
            query_condition: 查询条件
            result_count: 结果数量
        """
        event_type_map = {
            'read': AuditEventType.DATA_READ,
            'create': AuditEventType.DATA_CREATE,
            'update': AuditEventType.DATA_UPDATE,
            'delete': AuditEventType.DATA_DELETE,
            'export': AuditEventType.DATA_EXPORT
        }

        event_type = event_type_map.get(access_type, AuditEventType.DATA_READ)

        self.log_action(
            user_id=user_id,
            username=username,
            action=access_type,
            resource=data_type,
            resource_id=str(data_id),
            ip_address=ip_address,
            details=json.dumps({
                'query_condition': query_condition,
                'result_count': result_count
            }),
            event_type=event_type
        )

        # 记录到数据库
        self._record_data_access_to_db(user_id, username, data_type, data_id,
                                       access_type, query_condition, result_count, ip_address)

    def log_security_event(self, event_type: str, severity: int,
                           source: str, user_id: int = None,
                           username: str = None, ip_address: str = None,
                           description: str = None, raw_data: str = None):
        """
        记录安全事件

        Args:
            event_type: 事件类型
            severity: 严重程度
            source: 来源
            user_id: 用户ID
            username: 用户名
            ip_address: IP地址
            description: 描述
            raw_data: 原始数据
        """
        self.log_action(
            user_id=user_id,
            username=username,
            action='security_event',
            resource='security',
            ip_address=ip_address,
            risk_level=severity,
            details=json.dumps({
                'event_type': event_type,
                'source': source,
                'description': description,
                'raw_data': raw_data
            }),
            event_type=AuditEventType.ABNORMAL_ACCESS
        )

        # 记录到数据库
        self._record_security_event_to_db(event_type, severity, source,
                                          user_id, username, ip_address,
                                          description, raw_data)

    def _record_login_to_db(self, user_id: int, username: str,
                            success: bool, ip_address: str,
                            user_agent: str, failure_reason: str):
        """记录登录日志到数据库"""
        try:
            from core.database import get_db
            db = get_db()
            db.execute(
                """
                INSERT INTO login_logs
                (user_id, username, login_time, ip_address, user_agent, login_status, failure_reason)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, datetime.now(), ip_address, user_agent,
                 1 if success else 0, failure_reason)
            )
        except Exception as e:
            logger.error(f"记录登录日志到数据库失败: {e}")

    def _record_data_access_to_db(self, user_id: int, username: str,
                                   data_type: str, data_id: int,
                                   access_type: str, query_condition: str,
                                   result_count: int, ip_address: str):
        """记录数据访问日志到数据库"""
        try:
            from core.database import get_db
            db = get_db()
            db.execute(
                """
                INSERT INTO data_access_logs
                (user_id, username, data_type, data_id, access_type,
                 query_condition, result_count, ip_address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username, data_type, data_id, access_type,
                 query_condition, result_count, ip_address)
            )
        except Exception as e:
            logger.error(f"记录数据访问日志到数据库失败: {e}")

    def _record_security_event_to_db(self, event_type: str, severity: int,
                                      source: str, user_id: int,
                                      username: str, ip_address: str,
                                      description: str, raw_data: str):
        """记录安全事件到数据库"""
        try:
            from core.database import get_db
            db = get_db()
            db.execute(
                """
                INSERT INTO security_events
                (event_type, severity, source, user_id, username,
                 ip_address, description, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_type, severity, source, user_id, username,
                 ip_address, description, raw_data)
            )
        except Exception as e:
            logger.error(f"记录安全事件到数据库失败: {e}")

    def _alert_high_risk(self, log_entry: AuditLog):
        """高风险操作告警"""
        alert_msg = f"""
[安全告警] 检测到高风险操作
时间: {log_entry.timestamp}
用户: {log_entry.username} (ID: {log_entry.user_id})
IP: {log_entry.ip_address}
操作: {log_entry.event_name}
资源: {log_entry.resource}
详情: {log_entry.details}
"""
        logger.warning(alert_msg)

    def get_recent_logs(self, count: int = 100) -> List[Dict]:
        """
        获取最近的日志

        Args:
            count: 数量

        Returns:
            List[Dict]: 日志列表
        """
        with self._cache_lock:
            return [asdict(log) for log in self._log_cache[-count:]]

    def query_logs(self, user_id: int = None, username: str = None,
                   event_type: int = None, resource: str = None,
                   start_time: datetime = None, end_time: datetime = None,
                   risk_level: int = None, limit: int = 100) -> List[Dict]:
        """
        查询日志

        Args:
            user_id: 用户ID
            username: 用户名
            event_type: 事件类型
            resource: 资源
            start_time: 开始时间
            end_time: 结束时间
            risk_level: 风险级别
            limit: 返回数量限制

        Returns:
            List[Dict]: 日志列表
        """
        try:
            from core.database import get_db
            db = get_db()

            conditions = []
            params = []

            if user_id:
                conditions.append("user_id = ?")
                params.append(user_id)
            if username:
                conditions.append("username = ?")
                params.append(username)
            if event_type:
                conditions.append("event_type = ?")
                params.append(event_type)
            if resource:
                conditions.append("resource = ?")
                params.append(resource)
            if start_time:
                conditions.append("created_at >= ?")
                params.append(start_time)
            if end_time:
                conditions.append("created_at <= ?")
                params.append(end_time)
            if risk_level:
                conditions.append("risk_level >= ?")
                params.append(risk_level)

            where_clause = " AND ".join(conditions) if conditions else "1=1"
            query = f"""
                SELECT * FROM audit_logs
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ?
            """
            params.append(limit)

            return db.fetch_all(query, tuple(params))
        except Exception as e:
            logger.error(f"查询日志失败: {e}")
            return []

    def get_user_activity_summary(self, user_id: int,
                                  days: int = 7) -> Dict[str, Any]:
        """
        获取用户活动摘要

        Args:
            user_id: 用户ID
            days: 统计天数

        Returns:
            Dict: 活动摘要
        """
        try:
            from core.database import get_db
            db = get_db()

            start_time = datetime.now() - timedelta(days=days)

            # 操作统计
            action_stats = db.fetch_all(
                """
                SELECT action, COUNT(*) as count
                FROM audit_logs
                WHERE user_id = ? AND created_at >= ?
                GROUP BY action
                ORDER BY count DESC
                """,
                (user_id, start_time)
            )

            # 登录统计
            login_stats = db.fetch_one(
                """
                SELECT COUNT(*) as total_logins,
                       MAX(login_time) as last_login
                FROM login_logs
                WHERE user_id = ? AND login_status = 1 AND login_time >= ?
                """,
                (user_id, start_time)
            )

            # 数据访问统计
            access_stats = db.fetch_all(
                """
                SELECT data_type, COUNT(*) as count
                FROM data_access_logs
                WHERE user_id = ? AND created_at >= ?
                GROUP BY data_type
                """,
                (user_id, start_time)
            )

            return {
                'user_id': user_id,
                'period_days': days,
                'actions': {s['action']: s['count'] for s in action_stats},
                'total_logins': login_stats['total_logins'] if login_stats else 0,
                'last_login': login_stats['last_login'] if login_stats else None,
                'data_access': {s['data_type']: s['count'] for s in access_stats}
            }
        except Exception as e:
            logger.error(f"获取用户活动摘要失败: {e}")
            return {}

    def analyze_security_events(self, hours: int = 24) -> Dict[str, Any]:
        """
        分析安全事件

        Args:
            hours: 分析时间范围（小时）

        Returns:
            Dict: 分析结果
        """
        try:
            from core.database import get_db
            db = get_db()

            start_time = datetime.now() - timedelta(hours=hours)

            # 失败登录统计
            failed_logins = db.fetch_all(
                """
                SELECT username, ip_address, COUNT(*) as count
                FROM login_logs
                WHERE login_status = 0 AND login_time >= ?
                GROUP BY username, ip_address
                HAVING count >= 3
                ORDER BY count DESC
                """,
                (start_time,)
            )

            # 高风险操作统计
            high_risk_ops = db.fetch_all(
                """
                SELECT username, action, COUNT(*) as count
                FROM audit_logs
                WHERE risk_level >= 3 AND created_at >= ?
                GROUP BY username, action
                ORDER BY count DESC
                """,
                (start_time,)
            )

            # 安全事件统计
            security_events = db.fetch_all(
                """
                SELECT event_type, severity, COUNT(*) as count
                FROM security_events
                WHERE created_at >= ?
                GROUP BY event_type, severity
                ORDER BY severity DESC, count DESC
                """,
                (start_time,)
            )

            return {
                'period_hours': hours,
                'failed_login_attempts': failed_logins,
                'high_risk_operations': high_risk_ops,
                'security_events': security_events,
                'alert_count': len(failed_logins) + len(high_risk_ops) + len(security_events)
            }
        except Exception as e:
            logger.error(f"分析安全事件失败: {e}")
            return {}


if __name__ == '__main__':
    # 测试审计日志
    print("=" * 60)
    print("审计日志模块测试")
    print("=" * 60)

    # 创建审计日志记录器
    audit = AuditLogger('test_audit.log')

    # 测试登录日志
    print("\n1. 测试登录日志")
    audit.log_login_attempt(
        user_id=1,
        username='admin',
        success=True,
        ip_address='192.168.1.100',
        user_agent='Mozilla/5.0'
    )

    audit.log_login_attempt(
        username='hacker',
        success=False,
        ip_address='10.0.0.1',
        failure_reason='密码错误'
    )

    # 测试操作日志
    print("\n2. 测试操作日志")
    audit.log_action(
        user_id=1,
        username='admin',
        action='create_user',
        resource='user',
        resource_id='2',
        ip_address='192.168.1.100',
        risk_level=RiskLevel.MEDIUM,
        details='创建用户: test_user'
    )

    # 测试数据访问日志
    print("\n3. 测试数据访问日志")
    audit.log_data_access(
        user_id=1,
        username='admin',
        data_type='student',
        data_id=100,
        access_type='read',
        ip_address='192.168.1.100',
        result_count=10
    )

    # 测试安全事件
    print("\n4. 测试安全事件")
    audit.log_security_event(
        event_type='brute_force',
        severity=RiskLevel.HIGH,
        source='login',
        username='attacker',
        ip_address='10.0.0.1',
        description='检测到暴力破解尝试'
    )

    # 获取最近日志
    print("\n5. 最近日志")
    recent = audit.get_recent_logs(5)
    for log in recent:
        print(f"  {log['timestamp']}: {log['event_name']} by {log['username']}")

    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)