# 校园多源敏感数据一体化安全防护系统

## 项目简介

本项目是一个面向校园多源敏感数据的一体化安全防护系统，实现了RBAC权限控制、国密SM4加密、差分隐私保护、敏感数据脱敏、安全审计等核心安全功能。系统提供基于Flask的Web管理界面，支持学生和教职工敏感数据的安全存储、加密保护、脱敏展示和统计分析。

## 技术特点

### 1. RBAC权限控制系统
- 五角色权限模型：管理员(Admin)、安全员(Security)、审计员(Auditor)、普通用户(User)、访客(Guest)
- 25+细粒度权限控制，覆盖用户、角色、数据、加密、隐私、审计、系统等资源
- 动态权限检查装饰器（`@permission_required`、`@role_required`、`@admin_required`）
- 基于角色的动态脱敏策略

### 2. 国密SM4加密
- 完整实现国密SM4分组密码算法（GM/T 0002-2012）
- 支持ECB、CBC、CTR多种加密模式
- 字段级敏感数据加密存储（姓名、身份证、手机号、邮箱、地址、薪资等）
- 文件加密/解密功能
- PKCS7填充、随机IV/Nonce

### 3. 差分隐私保护
- 拉普拉斯机制（纯ε差分隐私）
- 高斯机制（(ε,δ)-差分隐私）
- 指数机制（非数值型选择）
- 隐私预算管理与追踪
- 统计查询保护（计数、均值、方差、直方图、分布）
- 查询结果对比展示

### 4. 敏感数据脱敏
- 6种脱敏策略：完全脱敏、部分脱敏、随机脱敏、哈希脱敏、截断脱敏、空值脱敏
- 支持多种数据类型：身份证号、手机号、邮箱、银行卡号、姓名、地址、密码、薪资、IP地址、日期
- 基于角色的脱敏策略引擎（不同角色看到不同程度的脱敏数据）
- 动态脱敏：查询结果自动根据用户角色应用脱敏规则

### 5. 安全审计日志
- 30+事件类型覆盖认证、用户管理、权限、数据操作、加密、系统操作、安全事件
- 4级风险等级：低(Low)、中(Medium)、高(High)、危急(Critical)
- 全链路操作记录：登录日志、数据访问日志、安全事件日志
- 日志文件轮转（50MB/文件，保留10个备份）
- 安全事件检测与处理（暴力破解、权限违规等）

### 6. 用户认证安全
- PBKDF2-HMAC-SHA256密码哈希（100,000次迭代，32字节盐，64字节哈希）
- 密码强度验证（大小写字母、数字、特殊字符，强度评分0-100）
- 登录失败锁定（5次失败后锁定30分钟）
- 密码有效期管理（90天）
- 常见弱密码检测

### 7. 数据管理与可视化
- 学生/教职工数据CRUD操作
- 全局搜索功能
- 数据导出（CSV格式，自动脱敏）
- 仪表盘统计与Chart.js图表（登录趋势、数据访问分布）
- RESTful API接口

## 安装部署

### 环境要求
- Python 3.8+
- SQLite3（Python内置）

### 安装步骤

```bash
# 1. 克隆项目
git clone https://github.com/your-repo/campus_security_system.git
cd campus_security_system

# 2. 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或 venv\Scripts\activate  # Windows

# 3. 安装依赖
pip install -r requirements.txt

# 4. 初始化并启动
python run.py --init
```

### 启动参数

```bash
# 初始化系统（创建数据库、默认用户、测试数据）并启动
python run.py --init

# 指定端口启动
python run.py --port 8080

# 启用调试模式
python run.py --debug

# 跳过初始化直接启动
python run.py --no-init
```

系统默认运行在 `http://127.0.0.1:5000`

## 测试账号

| 角色 | 用户名 | 密码 | 权限说明 |
|------|--------|------|----------|
| 系统管理员 | admin | Admin@123 | 所有权限 |
| 安全员 | security | Security@123 | 数据加密、解密、安全事件处理 |
| 审计员 | auditor | Auditor@123 | 审计日志查看、分析 |
| 普通用户 | user | User@123 | 数据查看、基本操作 |

## 项目结构

```
campus_security_system/
├── app.py                  # Flask应用工厂，初始化各模块
├── run.py                  # CLI启动脚本
├── README.md               # 项目文档
├── requirements.txt        # 依赖列表
├── login_page.html         # 独立登录页面
├── cookies.txt             # Cookie数据文件
│
├── core/                   # 核心安全模块
│   ├── __init__.py         # 包导出
│   ├── database.py         # 数据库管理器（SQLite, WAL模式, 线程安全）
│   ├── auth.py             # 用户认证（密码哈希、登录锁定、密码策略）
│   ├── rbac.py             # RBAC权限控制（5角色, 25+权限, 装饰器）
│   ├── encryption.py       # SM4加密（ECB/CBC/CTR, 字段加密, 文件加密）
│   ├── privacy.py          # 差分隐私（Laplace/Gaussian/指数机制, 预算追踪）
│   ├── masking.py          # 数据脱敏（6策略, 10+数据类型, 角色策略引擎）
│   └── audit.py            # 审计日志（30+事件类型, 风险等级, 安全事件分析）
│
├── app/                    # Flask应用包
│   ├── __init__.py
│   └── routes/             # 路由模块
│       ├── __init__.py
│       ├── auth.py         # 认证路由（登录、登出、改密、个人信息）
│       ├── main.py         # 主页路由（仪表盘、搜索、图表API）
│       ├── admin.py        # 管理路由（用户/角色/权限/安全事件/系统设置）
│       ├── data.py         # 数据路由（学生/教职工CRUD、隐私查询、文件加密、导出）
│       └── api.py          # RESTful API（用户/统计/审计/隐私/脱敏/健康检查）
│
├── utils/                  # 工具模块
│   ├── __init__.py         # 包导出
│   ├── config.py           # 配置管理（开发/生产/测试环境配置）
│   ├── logger.py           # 日志配置（文件轮转 + 控制台输出）
│   ├── forms.py            # WTForms表单定义（登录、改密、用户、学生、教职工等）
│   └── helpers.py          # 辅助函数（测试数据生成、校验、CSV导出、分页）
│
├── templates/              # Jinja2 HTML模板
│   ├── base.html           # 基础布局（Bootstrap 5, Font Awesome, 响应式导航）
│   ├── auth/               # 认证页面（登录、改密、个人信息）
│   ├── main/               # 主页面（仪表盘、关于、帮助、搜索结果）
│   ├── admin/              # 管理页面（用户管理、角色管理、安全事件、系统设置）
│   ├── data/               # 数据页面（学生/教职工列表、隐私查询、文件加密）
│   └── errors/             # 错误页面（403, 404, 500）
│
├── static/                 # 静态资源
│   ├── css/style.css       # 自定义样式（CSS变量、卡片动画、响应式）
│   └── js/main.js          # 客户端工具（AJAX、图表、通知、会话检查）
│
├── data/                   # SQLite数据库目录
│   └── campus_security.db  # 主数据库（14张表）
│
├── logs/                   # 日志目录
│   ├── app.log             # 应用日志
│   └── audit.log           # 审计日志
│
├── exports/                # 数据导出目录
└── uploads/                # 文件上传目录
```

## 数据库表结构

系统使用SQLite数据库，包含以下14张表：

| 表名 | 说明 |
|------|------|
| users | 系统用户账号 |
| roles | 角色定义（admin, security, auditor, user, guest） |
| permissions | 权限定义（25+条） |
| role_permissions | 角色-权限关联表 |
| students | 学生记录（含明文和加密字段） |
| staff | 教职工记录（含加密薪资等敏感字段） |
| sensitive_data | 通用敏感数据存储 |
| audit_logs | 操作审计日志 |
| login_logs | 登录日志（成功/失败） |
| data_access_logs | 数据访问追踪 |
| privacy_queries | 差分隐私查询日志 |
| encrypted_files | 文件加密记录 |
| system_config | 系统配置（键值对） |
| security_events | 安全事件记录 |

## API接口

系统提供RESTful API，主要端点包括：

| 路径 | 方法 | 说明 |
|------|------|------|
| `/api/health` | GET | 健康检查 |
| `/api/version` | GET | 系统版本 |
| `/api/users` | GET | 用户列表 |
| `/api/users/<id>` | GET | 用户详情 |
| `/api/stats/overview` | GET | 统计概览 |
| `/api/stats/login-trend` | GET | 登录趋势 |
| `/api/stats/data-access` | GET | 数据访问统计 |
| `/api/audit/logs` | GET | 审计日志查询 |
| `/api/audit/analysis` | GET | 审计分析 |
| `/api/privacy/demo` | GET | 差分隐私演示 |
| `/api/privacy/epsilon-comparison` | GET | 隐私预算对比 |
| `/api/masking/demo` | GET | 脱敏演示 |
| `/api/chart/login-trend` | GET | 登录趋势图表数据 |
| `/api/chart/access-distribution` | GET | 访问分布图表数据 |

## 核心功能演示

### 1. SM4加密演示

```python
from core.encryption import SM4Encryptor

# 创建加密器
encryptor = SM4Encryptor()

# 加密数据（默认CBC模式，返回base64编码字符串）
plaintext = "敏感数据"
ciphertext = encryptor.encrypt(plaintext)
print(f"加密结果: {ciphertext}")

# 解密数据
decrypted = encryptor.decrypt(ciphertext)
print(f"解密结果: {decrypted}")

# 指定加密模式
ciphertext_ecb = encryptor.encrypt(plaintext, mode='ECB')
ciphertext_cbc = encryptor.encrypt(plaintext, mode='CBC')
ciphertext_ctr = encryptor.encrypt(plaintext, mode='CTR')
```

### 2. 差分隐私查询演示

```python
from core.privacy import DifferentialPrivacy

# 创建差分隐私引擎
dp = DifferentialPrivacy(epsilon=1.0)

# 差分隐私计数
true_count = 100
noisy_count = dp.noisy_count(true_count)
print(f"真实值: {true_count}, 噪声值: {noisy_count}")

# 差分隐私均值
values = [85, 90, 78, 92, 88]
noisy_mean = dp.noisy_mean(values)
print(f"真实均值: {sum(values)/len(values):.2f}, 噪声均值: {noisy_mean:.2f}")

# 差分隐私直方图
data = ['A', 'B', 'A', 'C', 'B', 'A']
noisy_hist = dp.noisy_histogram(data, categories=['A', 'B', 'C'])
print(f"噪声直方图: {noisy_hist}")
```

### 3. 数据脱敏演示

```python
from core.masking import DataMasker

# 创建脱敏器
masker = DataMasker()

# 脱敏各类敏感数据
print(masker.mask_id_card("320102199001011234"))      # 320102********1234
print(masker.mask_phone("13812345678"))                # 138****5678
print(masker.mask_email("zhangsan@example.com"))       # zha******@example.com
print(masker.mask_name("张三"))                         # 张*
print(masker.mask_bank_card("6222021234567890123"))    # 6222*********0123
print(masker.mask_salary(15000))                       # 随机扰动 (0.8x~1.2x)
print(masker.mask_ip_address("192.168.1.100"))         # 192.168.1.*
```

## 安全特性

1. **密码安全**
   - PBKDF2-HMAC-SHA256哈希（100,000次迭代）
   - 密码强度验证与评分
   - 登录失败锁定（5次/30分钟）
   - 密码有效期（90天）
   - 常见弱密码检测

2. **会话安全**
   - 安全Cookie设置（HttpOnly, SameSite=Lax）
   - CSRF保护（Flask-WTF）
   - 会话超时（2小时）

3. **数据安全**
   - SM4国密算法加密存储
   - 动态数据脱敏（基于角色策略）
   - 细粒度访问控制
   - 文件加密/解密

4. **审计追踪**
   - 全链路操作日志记录
   - 安全事件告警与处理
   - 异常行为检测（暴力破解、权限违规）
   - 4级风险等级分类

## 技术栈

| 层级 | 技术 |
|------|------|
| **语言** | Python 3.8+ |
| **Web框架** | Flask 3.0.0 |
| **用户认证** | Flask-Login 0.6.3 |
| **CSRF防护** | Flask-WTF 1.2.1 / WTForms 3.1.1 |
| **密码哈希** | PBKDF2-HMAC-SHA256（标准库hashlib） |
| **加密算法** | 国密SM4（纯Python实现，GM/T 0002-2012） |
| **数据库** | SQLite3（标准库，WAL模式） |
| **数据处理** | NumPy 1.26.2, Pandas 2.1.4 |
| **前端CSS** | Bootstrap 5.3, Font Awesome 4.7 |
| **前端JS** | Chart.js（图表可视化） |
| **表单验证** | WTForms 3.1.1, email-validator 2.1.0 |
| **测试** | pytest 7.4.3, pytest-cov 4.1.0 |
| **代码质量** | flake8 6.1.0, black 23.12.1 |
| **环境管理** | python-dotenv 1.0.0 |

## 配置说明

系统支持多环境配置：

| 环境 | 类名 | 说明 |
|------|------|------|
| 开发环境 | `DevelopmentConfig` | DEBUG=True，适合本地开发 |
| 生产环境 | `ProductionConfig` | DEBUG=False，Secure Cookie，必须设置SECRET_KEY |
| 测试环境 | `TestingConfig` | 内存数据库，关闭CSRF |

主要配置项（在 `utils/config.py` 中）：
- `SECRET_KEY`：Flask密钥（可通过环境变量设置）
- `SM4_KEY`：SM4加密密钥（128位，32字符十六进制）
- `DP_EPSILON`：差分隐私默认隐私预算（1.0）
- `MAX_LOGIN_ATTEMPTS`：最大登录失败次数（5）
- `PASSWORD_MAX_AGE_DAYS`：密码有效期（90天）
- `PERMANENT_SESSION_LIFETIME`：会话超时（2小时）

## 开发团队

挑战杯参赛团队 - 网络安全赛道

## 许可证

本项目仅供学习和研究使用。

---

© 2024 挑战杯参赛团队 | 网络安全赛道
