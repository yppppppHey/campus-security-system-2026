#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
差分隐私模块
实现差分隐私保护机制，用于统计查询的隐私保护

功能:
    - 拉普拉斯机制
    - 指数机制
    - 隐私预算管理
    - 噪声数据生成
    - 统计查询保护

参考: Dwork, C. (2006). Differential Privacy
"""

import math
import random
import numpy as np
from typing import Union, List, Dict, Any, Callable, Tuple, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class DifferentialPrivacy:
    """
    差分隐私引擎
    提供多种差分隐私机制实现
    """

    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5):
        """
        初始化差分隐私引擎

        Args:
            epsilon: 隐私预算，越小隐私保护越强
            delta: 失败概率，用于近似差分隐私
        """
        if epsilon <= 0:
            raise ValueError("epsilon必须大于0")
        if delta < 0 or delta >= 1:
            raise ValueError("delta必须在[0, 1)范围内")

        self.epsilon = epsilon
        self.delta = delta
        self.total_budget_used = 0.0
        self.query_history = []

        logger.info(f"差分隐私引擎初始化: ε={epsilon}, δ={delta}")

    def laplace_noise(self, sensitivity: float = 1.0) -> float:
        """
        生成拉普拉斯噪声

        Args:
            sensitivity: 查询敏感度

        Returns:
            float: 噪声值
        """
        scale = sensitivity / self.epsilon
        # 拉普拉斯分布采样
        u = random.random() - 0.5
        noise = -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))
        return noise

    def gaussian_noise(self, sensitivity: float = 1.0) -> float:
        """
        生成高斯噪声（用于(ε,δ)-差分隐私）

        Args:
            sensitivity: 查询敏感度

        Returns:
            float: 噪声值
        """
        sigma = sensitivity * math.sqrt(2 * math.log(1.25 / self.delta)) / self.epsilon
        noise = np.random.normal(0, sigma)
        return noise

    def add_noise_to_value(self, value: Union[int, float],
                           sensitivity: float = 1.0,
                           mechanism: str = 'laplace') -> float:
        """
        为数值添加噪声

        Args:
            value: 原始值
            sensitivity: 敏感度
            mechanism: 噪声机制 ('laplace' 或 'gaussian')

        Returns:
            float: 添加噪声后的值
        """
        if mechanism == 'laplace':
            noise = self.laplace_noise(sensitivity)
        elif mechanism == 'gaussian':
            noise = self.gaussian_noise(sensitivity)
        else:
            raise ValueError(f"未知的噪声机制: {mechanism}")

        return value + noise

    def noisy_count(self, true_count: int, sensitivity: int = 1) -> int:
        """
        差分隐私计数查询

        Args:
            true_count: 真实计数
            sensitivity: 敏感度（默认为1，因为增删一条记录计数变化1）

        Returns:
            int: 添加噪声后的计数
        """
        noisy_value = self.add_noise_to_value(true_count, sensitivity)
        # 计数不能为负
        return max(0, int(round(noisy_value)))

    def noisy_sum(self, true_sum: float, sensitivity: float) -> float:
        """
        差分隐私求和查询

        Args:
            true_sum: 真实和
            sensitivity: 敏感度（数据范围）

        Returns:
            float: 添加噪声后的和
        """
        return self.add_noise_to_value(true_sum, sensitivity)

    def noisy_mean(self, data: List[float], lower: float, upper: float) -> float:
        """
        差分隐私均值查询

        Args:
            data: 数据列表
            lower: 数据下界
            upper: 数据上界

        Returns:
            float: 添加噪声后的均值
        """
        if not data:
            return 0.0

        n = len(data)
        # 裁剪数据到指定范围
        clipped_data = [max(lower, min(upper, x)) for x in data]
        true_mean = sum(clipped_data) / n

        # 均值的敏感度为 (upper - lower) / n
        sensitivity = (upper - lower) / n
        noisy_mean = self.add_noise_to_value(true_mean, sensitivity)

        # 确保结果在合理范围内
        return max(lower, min(upper, noisy_mean))

    def noisy_variance(self, data: List[float], lower: float, upper: float) -> float:
        """
        差分隐私方差查询

        Args:
            data: 数据列表
            lower: 数据下界
            upper: 数据上界

        Returns:
            float: 添加噪声后的方差
        """
        if len(data) < 2:
            return 0.0

        n = len(data)
        # 裁剪数据
        clipped_data = [max(lower, min(upper, x)) for x in data]
        true_mean = sum(clipped_data) / n
        true_variance = sum((x - true_mean) ** 2 for x in clipped_data) / n

        # 方差的敏感度
        range_sq = (upper - lower) ** 2
        sensitivity = range_sq / n

        noisy_variance = self.add_noise_to_value(true_variance, sensitivity)
        return max(0, noisy_variance)

    def noisy_histogram(self, data: List[Any], bins: List[Any],
                       sensitivity: int = 1) -> Dict[Any, int]:
        """
        差分隐私直方图

        Args:
            data: 数据列表
            bins: 分箱列表
            sensitivity: 敏感度

        Returns:
            Dict: 添加噪声后的直方图
        """
        # 计算真实直方图
        true_hist = {bin_val: 0 for bin_val in bins}
        for item in data:
            if item in bins:
                true_hist[item] += 1

        # 添加噪声
        noisy_hist = {}
        for bin_val, count in true_hist.items():
            noisy_hist[bin_val] = self.noisy_count(count, sensitivity)

        return noisy_hist

    def exponential_mechanism(self, candidates: List[Any],
                              score_function: Callable[[Any], float],
                              sensitivity: float = 1.0) -> Any:
        """
        指数机制（用于非数值型数据的选择）

        Args:
            candidates: 候选列表
            score_function: 评分函数
            sensitivity: 评分函数敏感度

        Returns:
            Any: 选中的候选
        """
        if not candidates:
            raise ValueError("候选列表不能为空")

        # 计算每个候选的得分
        scores = [(c, score_function(c)) for c in candidates]

        # 计算选择概率
        max_score = max(s for _, s in scores)
        probabilities = [
            math.exp(self.epsilon * s / (2 * sensitivity))
            for _, s in scores
        ]

        # 归一化
        total = sum(probabilities)
        probabilities = [p / total for p in probabilities]

        # 按概率选择
        selected = random.choices(candidates, weights=probabilities, k=1)[0]

        return selected

    def report_noisy_max(self, candidates: List[Any],
                        score_function: Callable[[Any], float],
                        sensitivity: float = 1.0) -> Any:
        """
        报告噪声最大值机制

        Args:
            candidates: 候选列表
            score_function: 评分函数
            sensitivity: 敏感度

        Returns:
            Any: 选中的候选
        """
        if not candidates:
            raise ValueError("候选列表不能为空")

        # 为每个候选的得分添加噪声
        noisy_scores = []
        for candidate in candidates:
            score = score_function(candidate)
            noise = self.laplace_noise(sensitivity)
            noisy_scores.append((candidate, score + noise))

        # 返回噪声得分最高的候选
        return max(noisy_scores, key=lambda x: x[1])[0]

    def privacy_budget_check(self, additional_budget: float) -> bool:
        """
        检查隐私预算是否足够

        Args:
            additional_budget: 需要的额外预算

        Returns:
            bool: 是否有足够预算
        """
        return self.total_budget_used + additional_budget <= self.epsilon

    def consume_budget(self, amount: float):
        """
        消耗隐私预算

        Args:
            amount: 消耗的预算量
        """
        self.total_budget_used += amount
        logger.info(f"消耗隐私预算: {amount}, 已用: {self.total_budget_used}/{self.epsilon}")

    def remaining_budget(self) -> float:
        """
        获取剩余隐私预算

        Returns:
            float: 剩余预算
        """
        return max(0, self.epsilon - self.total_budget_used)

    def record_query(self, query_type: str, params: Dict[str, Any],
                    original_result: Any, noisy_result: Any):
        """
        记录查询历史

        Args:
            query_type: 查询类型
            params: 查询参数
            original_result: 原始结果
            noisy_result: 噪声结果
        """
        record = {
            'timestamp': datetime.now().isoformat(),
            'query_type': query_type,
            'params': params,
            'original_result': original_result,
            'noisy_result': noisy_result,
            'epsilon_used': self.epsilon,
            'total_budget_used': self.total_budget_used
        }
        self.query_history.append(record)

    def get_query_history(self) -> List[Dict]:
        """获取查询历史"""
        return self.query_history.copy()

    def reset_budget(self):
        """重置隐私预算"""
        self.total_budget_used = 0.0
        logger.info("隐私预算已重置")


class PrivacyQueryEngine:
    """
    隐私查询引擎
    封装常用的差分隐私统计查询
    """

    def __init__(self, dp_engine: DifferentialPrivacy):
        """
        初始化查询引擎

        Args:
            dp_engine: 差分隐私引擎实例
        """
        self.dp = dp_engine

    def query_student_count_by_department(self, data: List[Dict],
                                          department: str) -> int:
        """
        按院系统计学生人数（差分隐私）

        Args:
            data: 学生数据列表
            department: 院系名称

        Returns:
            int: 添加噪声后的学生人数
        """
        true_count = sum(1 for d in data if d.get('department') == department)
        noisy_count = self.dp.noisy_count(true_count)

        self.dp.record_query(
            'student_count_by_department',
            {'department': department},
            true_count,
            noisy_count
        )

        return noisy_count

    def query_average_score(self, data: List[Dict], score_field: str,
                           min_score: float = 0, max_score: float = 100) -> float:
        """
        查询平均分（差分隐私）

        Args:
            data: 数据列表
            score_field: 分数字段名
            min_score: 最低分
            max_score: 最高分

        Returns:
            float: 添加噪声后的平均分
        """
        scores = [d.get(score_field, 0) for d in data if score_field in d]
        noisy_mean = self.dp.noisy_mean(scores, min_score, max_score)

        self.dp.record_query(
            'average_score',
            {'score_field': score_field},
            sum(scores) / len(scores) if scores else 0,
            noisy_mean
        )

        return noisy_mean

    def query_age_distribution(self, data: List[Dict],
                               age_range: Tuple[int, int] = (15, 35)) -> Dict[int, int]:
        """
        查询年龄分布（差分隐私）

        Args:
            data: 数据列表
            age_range: 年龄范围

        Returns:
            Dict[int, int]: 添加噪声后的年龄分布
        """
        # 计算年龄
        current_year = datetime.now().year
        ages = []
        for d in data:
            birth_date = d.get('birth_date')
            if birth_date:
                if isinstance(birth_date, str):
                    birth_year = int(birth_date[:4])
                else:
                    birth_year = birth_date.year
                ages.append(current_year - birth_year)

        # 创建年龄分箱
        bins = list(range(age_range[0], age_range[1] + 1))
        noisy_hist = self.dp.noisy_histogram(ages, bins)

        self.dp.record_query(
            'age_distribution',
            {'age_range': age_range},
            {b: ages.count(b) for b in bins},
            noisy_hist
        )

        return noisy_hist

    def query_gender_ratio(self, data: List[Dict]) -> Dict[str, float]:
        """
        查询性别比例（差分隐私）

        Args:
            data: 数据列表

        Returns:
            Dict[str, float]: 添加噪声后的性别比例
        """
        # 计算真实计数
        male_count = sum(1 for d in data if d.get('gender') == '男')
        female_count = sum(1 for d in data if d.get('gender') == '女')
        total = male_count + female_count

        # 添加噪声
        noisy_male = self.dp.noisy_count(male_count)
        noisy_female = self.dp.noisy_count(female_count)
        noisy_total = noisy_male + noisy_female

        ratio = {
            'male_count': noisy_male,
            'female_count': noisy_female,
            'male_ratio': noisy_male / noisy_total if noisy_total > 0 else 0.5,
            'female_ratio': noisy_female / noisy_total if noisy_total > 0 else 0.5
        }

        self.dp.record_query(
            'gender_ratio',
            {},
            {'male': male_count, 'female': female_count},
            ratio
        )

        return ratio

    def query_salary_statistics(self, data: List[Dict],
                                min_salary: float = 0,
                                max_salary: float = 100000) -> Dict[str, float]:
        """
        查询薪资统计（差分隐私）

        Args:
            data: 数据列表
            min_salary: 最低薪资
            max_salary: 最高薪资

        Returns:
            Dict[str, float]: 添加噪声后的薪资统计
        """
        salaries = [d.get('salary', 0) for d in data if 'salary' in d]

        if not salaries:
            return {'mean': 0, 'variance': 0, 'min': 0, 'max': 0}

        noisy_mean = self.dp.noisy_mean(salaries, min_salary, max_salary)
        noisy_var = self.dp.noisy_variance(salaries, min_salary, max_salary)

        # 对于min/max，使用更保守的方法
        noisy_min = max(min_salary, self.dp.add_noise_to_value(min(salaries), max_salary - min_salary))
        noisy_max = min(max_salary, self.dp.add_noise_to_value(max(salaries), max_salary - min_salary))

        stats = {
            'mean': noisy_mean,
            'variance': noisy_var,
            'std': math.sqrt(max(0, noisy_var)),
            'min': noisy_min,
            'max': noisy_max
        }

        self.dp.record_query(
            'salary_statistics',
            {'range': (min_salary, max_salary)},
            {'mean': sum(salaries) / len(salaries), 'variance': np.var(salaries) if len(salaries) > 1 else 0},
            stats
        )

        return stats


class PrivacyBudgetTracker:
    """
    隐私预算追踪器
    用于追踪和管理多个查询的隐私预算消耗
    """

    def __init__(self, total_budget: float):
        """
        初始化预算追踪器

        Args:
            total_budget: 总隐私预算
        """
        self.total_budget = total_budget
        self.used_budget = 0.0
        self.query_log = []

    def allocate(self, epsilon: float, query_name: str) -> bool:
        """
        分配隐私预算

        Args:
            epsilon: 请求的预算
            query_name: 查询名称

        Returns:
            bool: 是否成功分配
        """
        if self.used_budget + epsilon > self.total_budget:
            logger.warning(f"隐私预算不足: 请求{epsilon}, 剩余{self.remaining()}")
            return False

        self.used_budget += epsilon
        self.query_log.append({
            'query': query_name,
            'epsilon': epsilon,
            'timestamp': datetime.now().isoformat()
        })

        return True

    def remaining(self) -> float:
        """获取剩余预算"""
        return self.total_budget - self.used_budget

    def usage_ratio(self) -> float:
        """获取预算使用比例"""
        return self.used_budget / self.total_budget

    def get_report(self) -> Dict:
        """获取预算使用报告"""
        return {
            'total_budget': self.total_budget,
            'used_budget': self.used_budget,
            'remaining_budget': self.remaining(),
            'usage_ratio': self.usage_ratio(),
            'query_count': len(self.query_log),
            'queries': self.query_log
        }


if __name__ == '__main__':
    # 测试差分隐私
    print("=" * 60)
    print("差分隐私模块测试")
    print("=" * 60)

    # 创建差分隐私引擎
    dp = DifferentialPrivacy(epsilon=1.0, delta=1e-5)

    # 测试计数查询
    print("\n1. 计数查询测试")
    true_count = 100
    for _ in range(5):
        noisy = dp.noisy_count(true_count)
        print(f"  真实值: {true_count}, 噪声值: {noisy}, 误差: {abs(noisy - true_count)}")

    # 测试均值查询
    print("\n2. 均值查询测试")
    data = [random.gauss(50, 10) for _ in range(100)]
    true_mean = sum(data) / len(data)
    noisy_mean = dp.noisy_mean(data, 0, 100)
    print(f"  真实均值: {true_mean:.2f}")
    print(f"  噪声均值: {noisy_mean:.2f}")
    print(f"  误差: {abs(noisy_mean - true_mean):.2f}")

    # 测试直方图
    print("\n3. 直方图测试")
    categories = ['A', 'B', 'C', 'D']
    hist_data = [random.choice(categories) for _ in range(100)]
    true_hist = {c: hist_data.count(c) for c in categories}
    noisy_hist = dp.noisy_histogram(hist_data, categories)
    print(f"  真实分布: {true_hist}")
    print(f"  噪声分布: {noisy_hist}")

    # 测试指数机制
    print("\n4. 指数机制测试")
    candidates = ['选项A', '选项B', '选项C', '选项D']
    scores = {'选项A': 10, '选项B': 8, '选项C': 6, '选项D': 4}

    def score_func(x):
        return scores[x]

    results = {c: 0 for c in candidates}
    for _ in range(1000):
        selected = dp.exponential_mechanism(candidates, score_func)
        results[selected] += 1

    print(f"  选择结果: {results}")
    print(f"  (得分高的选项应被选中更多次)")

    # 测试隐私预算
    print("\n5. 隐私预算测试")
    tracker = PrivacyBudgetTracker(total_budget=2.0)
    print(f"  初始预算: {tracker.remaining()}")

    tracker.allocate(0.5, "查询1")
    print(f"  查询1后剩余: {tracker.remaining()}")

    tracker.allocate(0.8, "查询2")
    print(f"  查询2后剩余: {tracker.remaining()}")

    success = tracker.allocate(1.0, "查询3")
    print(f"  查询3分配{'成功' if success else '失败'}")
    print(f"  最终剩余: {tracker.remaining()}")
    print(f"  使用比例: {tracker.usage_ratio():.1%}")

    print("\n" + "=" * 60)
    print("测试完成")
    print("=" * 60)