/**
 * 校园安全防护系统 - 主JavaScript文件
 * Campus Security System - Main JavaScript
 */

// 全局配置
const CONFIG = {
    API_BASE: '/api',
    TIMEOUT: 30000,
    DEBUG: false
};

// 工具函数
const Utils = {
    // 格式化日期
    formatDate: function(date, format = 'YYYY-MM-DD HH:mm:ss') {
        if (!date) return '';
        const d = new Date(date);
        const year = d.getFullYear();
        const month = String(d.getMonth() + 1).padStart(2, '0');
        const day = String(d.getDate()).padStart(2, '0');
        const hours = String(d.getHours()).padStart(2, '0');
        const minutes = String(d.getMinutes()).padStart(2, '0');
        const seconds = String(d.getSeconds()).padStart(2, '0');

        return format
            .replace('YYYY', year)
            .replace('MM', month)
            .replace('DD', day)
            .replace('HH', hours)
            .replace('mm', minutes)
            .replace('ss', seconds);
    },

    // 格式化数字
    formatNumber: function(num) {
        if (!num) return '0';
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    },

    // 显示加载状态
    showLoading: function(element) {
        element.innerHTML = '<div class="text-center py-5"><div class="loading-spinner"></div><p class="mt-2">加载中...</p></div>';
    },

    // 显示错误
    showError: function(element, message) {
        element.innerHTML = `<div class="alert alert-danger"><i class="fa fa-times-circle"></i> ${message}</div>`;
    },

    // 显示成功
    showSuccess: function(message) {
        const alert = document.createElement('div');
        alert.className = 'alert alert-success alert-dismissible fade show';
        alert.innerHTML = `<i class="fa fa-check-circle"></i> ${message}<button type="button" class="btn-close" data-bs-dismiss="alert"></button>`;
        document.querySelector('main').prepend(alert);

        setTimeout(() => alert.remove(), 5000);
    },

    // AJAX请求
    ajax: function(url, options = {}) {
        const defaults = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            timeout: CONFIG.TIMEOUT
        };

        const settings = { ...defaults, ...options };

        return new Promise((resolve, reject) => {
            const xhr = new XMLHttpRequest();
            xhr.open(settings.method, url, true);

            for (const [key, value] of Object.entries(settings.headers)) {
                xhr.setRequestHeader(key, value);
            }

            xhr.timeout = settings.timeout;

            xhr.onload = function() {
                if (xhr.status >= 200 && xhr.status < 300) {
                    try {
                        resolve(JSON.parse(xhr.responseText));
                    } catch (e) {
                        resolve(xhr.responseText);
                    }
                } else {
                    reject(new Error(`HTTP ${xhr.status}: ${xhr.statusText}`));
                }
            };

            xhr.onerror = function() {
                reject(new Error('网络错误'));
            };

            xhr.ontimeout = function() {
                reject(new Error('请求超时'));
            };

            if (settings.body) {
                xhr.send(JSON.stringify(settings.body));
            } else {
                xhr.send();
            }
        });
    }
};

// API服务
const API = {
    // 获取统计数据
    getStats: async function() {
        return Utils.ajax(`${CONFIG.API_BASE}/stats/overview`);
    },

    // 获取登录趋势
    getLoginTrend: async function(days = 7) {
        return Utils.ajax(`${CONFIG.API_BASE}/stats/login-trend?days=${days}`);
    },

    // 获取数据访问统计
    getDataAccess: async function(days = 30) {
        return Utils.ajax(`${CONFIG.API_BASE}/stats/data-access?days=${days}`);
    },

    // 获取审计日志
    getAuditLogs: async function(params = {}) {
        const query = new URLSearchParams(params).toString();
        return Utils.ajax(`${CONFIG.API_BASE}/audit/logs?${query}`);
    },

    // 获取差分隐私演示数据
    getPrivacyDemo: async function() {
        return Utils.ajax(`${CONFIG.API_BASE}/privacy/demo`);
    },

    // 获取脱敏演示数据
    getMaskingDemo: async function() {
        return Utils.ajax(`${CONFIG.API_BASE}/masking/demo`);
    },

    // 健康检查
    healthCheck: async function() {
        return Utils.ajax(`${CONFIG.API_BASE}/health`);
    }
};

// 图表管理
const Charts = {
    instances: {}, // 存储图表实例

    // 创建折线图
    createLineChart: function(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId).getContext('2d');

        if (this.instances[canvasId]) {
            this.instances[canvasId].destroy();
        }

        const defaultOptions = {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: true,
                    position: 'top'
                }
            },
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        };

        this.instances[canvasId] = new Chart(ctx, {
            type: 'line',
            data: data,
            options: { ...defaultOptions, ...options }
        });

        return this.instances[canvasId];
    },

    // 创建柱状图
    createBarChart: function(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId).getContext('2d');

        if (this.instances[canvasId]) {
            this.instances[canvasId].destroy();
        }

        this.instances[canvasId] = new Chart(ctx, {
            type: 'bar',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                ...options
            }
        });

        return this.instances[canvasId];
    },

    // 创建饼图
    createPieChart: function(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId).getContext('2d');

        if (this.instances[canvasId]) {
            this.instances[canvasId].destroy();
        }

        this.instances[canvasId] = new Chart(ctx, {
            type: 'pie',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                },
                ...options
            }
        });

        return this.instances[canvasId];
    },

    // 创建环形图
    createDoughnutChart: function(canvasId, data, options = {}) {
        const ctx = document.getElementById(canvasId).getContext('2d');

        if (this.instances[canvasId]) {
            this.instances[canvasId].destroy();
        }

        this.instances[canvasId] = new Chart(ctx, {
            type: 'doughnut',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                },
                ...options
            }
        });

        return this.instances[canvasId];
    },

    // 更新图表数据
    updateChart: function(canvasId, newData) {
        if (this.instances[canvasId]) {
            this.instances[canvasId].data = newData;
            this.instances[canvasId].update();
        }
    },

    // 销毁图表
    destroyChart: function(canvasId) {
        if (this.instances[canvasId]) {
            this.instances[canvasId].destroy();
            delete this.instances[canvasId];
        }
    }
};

// 表单验证
const FormValidator = {
    // 验证规则
    rules: {
        required: function(value) {
            return value !== null && value !== undefined && value !== '';
        },
        email: function(value) {
            const pattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            return pattern.test(value);
        },
        phone: function(value) {
            const pattern = /^1[3-9]\d{9}$/;
            return pattern.test(value);
        },
        idCard: function(value) {
            const pattern = /^(\d{15}|\d{17}[\dX])$/;
            return pattern.test(value);
        },
        minLength: function(value, min) {
            return value.length >= min;
        },
        maxLength: function(value, max) {
            return value.length <= max;
        }
    },

    // 验证表单
    validate: function(form, rules) {
        const errors = {};

        for (const [field, fieldRules] of Object.entries(rules)) {
            const value = form[field]?.value;

            for (const [ruleName, ruleParam] of Object.entries(fieldRules)) {
                if (ruleName === 'required' && !this.rules.required(value)) {
                    errors[field] = '此字段为必填项';
                    break;
                }

                if (ruleName === 'email' && value && !this.rules.email(value)) {
                    errors[field] = '请输入有效的邮箱地址';
                    break;
                }

                if (ruleName === 'phone' && value && !this.rules.phone(value)) {
                    errors[field] = '请输入有效的手机号';
                    break;
                }

                if (ruleName === 'minLength' && !this.rules.minLength(value, ruleParam)) {
                    errors[field] = `最少需要${ruleParam}个字符`;
                    break;
                }

                if (ruleName === 'maxLength' && !this.rules.maxLength(value, ruleParam)) {
                    errors[field] = `最多允许${ruleParam}个字符`;
                    break;
                }
            }
        }

        return {
            valid: Object.keys(errors).length === 0,
            errors: errors
        };
    },

    // 显示错误
    showErrors: function(form, errors) {
        // 清除之前的错误
        form.querySelectorAll('.is-invalid').forEach(el => {
            el.classList.remove('is-invalid');
        });
        form.querySelectorAll('.invalid-feedback').forEach(el => {
            el.remove();
        });

        // 显示新错误
        for (const [field, message] of Object.entries(errors)) {
            const input = form[field];
            if (input) {
                input.classList.add('is-invalid');
                const feedback = document.createElement('div');
                feedback.className = 'invalid-feedback';
                feedback.textContent = message;
                input.parentNode.appendChild(feedback);
            }
        }
    }
};

// 页面初始化
document.addEventListener('DOMContentLoaded', function() {
    // 初始化Bootstrap组件
    initBootstrapComponents();

    // 初始化表单验证
    initFormValidation();

    // 初始化自动刷新
    initAutoRefresh();

    // 初始化工具提示
    initTooltips();
});

// 初始化Bootstrap组件
function initBootstrapComponents() {
    // 初始化所有下拉菜单
    const dropdowns = document.querySelectorAll('[data-bs-toggle="dropdown"]');
    dropdowns.forEach(dropdown => {
        new bootstrap.Dropdown(dropdown);
    });

    // 初始化所有模态框
    const modals = document.querySelectorAll('.modal');
    modals.forEach(modal => {
        new bootstrap.Modal(modal);
    });

    // 初始化所有工具提示
    const tooltips = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltips.forEach(tooltip => {
        new bootstrap.Tooltip(tooltip);
    });
}

// 初始化表单验证
function initFormValidation() {
    const forms = document.querySelectorAll('form[data-validate]');

    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            const rules = JSON.parse(this.dataset.validate || '{}');
            const result = FormValidator.validate(this, rules);

            if (!result.valid) {
                e.preventDefault();
                FormValidator.showErrors(this, result.errors);
            }
        });
    });
}

// 初始化自动刷新
function initAutoRefresh() {
    const autoRefreshElements = document.querySelectorAll('[data-auto-refresh]');

    autoRefreshElements.forEach(element => {
        const interval = parseInt(element.dataset.autoRefresh) || 30000;
        const url = element.dataset.refreshUrl;

        if (url) {
            setInterval(async () => {
                try {
                    const data = await Utils.ajax(url);
                    element.innerHTML = data.content || '';
                } catch (error) {
                    console.error('自动刷新失败:', error);
                }
            }, interval);
        }
    });
}

// 初始化工具提示
function initTooltips() {
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    tooltipTriggerList.forEach(tooltipTriggerEl => {
        new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// 导出模块
window.Utils = Utils;
window.API = API;
window.Charts = Charts;
window.FormValidator = FormValidator;