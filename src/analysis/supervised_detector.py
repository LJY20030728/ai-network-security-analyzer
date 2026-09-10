# -*- coding: utf-8 -*-
"""
监督学习检测器（主检测引擎）
基于 HistGradientBoostingClassifier，使用 CIC 风格 76 维流特征。
在 CIC-UNSW 44 万流上训练，二分类 F1=0.9487。

作为产品的主检测引擎，规则/基线/孤立森林作为可解释性辅助引擎。
"""
import os
from collections import defaultdict
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from loguru import logger

from ..capture.packet_parser import PacketInfo
from .cic_features import CICFlowExtractor, CIC_FEATURE_NAMES


class SupervisedDetector:
    """
    监督学习检测器
    加载预训练的 HistGradientBoosting 模型，对 PCAP 中的每个流进行预测，
    聚合为 PCAP 级的威胁判定。
    """

    MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "models", "supervised_detector.joblib"
    )

    # 攻击流比例阈值：超过此比例判定整个 PCAP 为攻击
    ATTACK_FLOW_RATIO_THRESHOLD = 0.05

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or self.MODEL_PATH
        self.model = None
        self.feature_names: List[str] = []
        self.categories: Dict[int, str] = {}
        self.metrics: Dict[str, float] = {}
        self.loaded = False
        self._cic_extractor = CICFlowExtractor()

    def load(self) -> bool:
        """加载模型文件"""
        if not os.path.exists(self.model_path):
            logger.warning(f"监督模型文件不存在: {self.model_path}")
            return False
        try:
            import joblib
            bundle = joblib.load(self.model_path)
            self.model = bundle["model"]
            self.feature_names = bundle.get("feature_names", CIC_FEATURE_NAMES)
            self.categories = bundle.get("categories", {})
            self.metrics = {
                "f1": bundle.get("binary_f1", 0.0),
                "precision": bundle.get("binary_precision", 0.0),
                "recall": bundle.get("binary_recall", 0.0),
                "accuracy": bundle.get("accuracy", 0.0),
            }
            self.loaded = True
            logger.info(
                f"监督模型加载成功 | F1={self.metrics['f1']} "
                f"P={self.metrics['precision']} R={self.metrics['recall']} "
                f"特征数={len(self.feature_names)}"
            )
            return True
        except Exception as e:
            logger.error(f"监督模型加载失败: {e}")
            return False

    def detect(self, packets: List[PacketInfo]) -> Dict[str, Any]:
        """
        对数据包列表进行监督检测
        :param packets: PacketInfo 列表
        :return: 检测结果字典
        """
        if not self.loaded:
            if not self.load():
                return {
                    "engine": "supervised",
                    "available": False,
                    "reason": "模型未加载",
                    "is_attack": False,
                    "confidence": 0.0,
                }

        # 提取 CIC 流特征
        flows = self._cic_extractor.extract(packets)
        if not flows:
            return {
                "engine": "supervised",
                "available": True,
                "total_flows": 0,
                "is_attack": False,
                "confidence": 0.0,
                "attack_flows": 0,
                "attack_flow_ratio": 0.0,
                "top_attack_flows": [],
            }

        # 批量预测
        features = np.array([f["features"] for f in flows], dtype=np.float64)
        try:
            # 二分类预测（0=Benign, !=0=Attack）
            predictions = self.model.predict(features)
            probabilities = self.model.predict_proba(features)
        except Exception as e:
            logger.error(f"监督模型预测失败: {e}")
            return {
                "engine": "supervised",
                "available": True,
                "is_attack": False,
                "confidence": 0.0,
                "error": str(e),
            }

        # 聚合结果
        attack_mask = predictions != 0
        attack_count = int(np.sum(attack_mask))
        total_count = len(flows)
        attack_ratio = attack_count / total_count if total_count > 0 else 0.0

        # 攻击流的平均置信度
        if attack_count > 0:
            attack_probs = probabilities[attack_mask]
            # 取攻击类别的最大概率作为置信度
            attack_confidences = np.max(attack_probs, axis=1)
            avg_confidence = float(np.mean(attack_confidences))
        else:
            avg_confidence = 0.0

        # PCAP 级判定：攻击流比例超过阈值，或聚合特征触发攻击模式
        is_attack = attack_ratio >= self.ATTACK_FLOW_RATIO_THRESHOLD
        aggregate_alert = self._aggregate_detection(packets, flows)
        if aggregate_alert["triggered"]:
            is_attack = True
            avg_confidence = max(avg_confidence, 0.85)  # 聚合触发的攻击给高置信度

        # 攻击类别分布
        category_counts = {}
        for pred in predictions[attack_mask]:
            cat_name = self.categories.get(int(pred), f"Category_{pred}")
            category_counts[cat_name] = category_counts.get(cat_name, 0) + 1

        # TOP 攻击流（按置信度排序）
        top_attack_flows = []
        if attack_count > 0:
            attack_indices = np.where(attack_mask)[0]
            attack_flow_confs = []
            for idx in attack_indices:
                f = flows[idx]
                conf = float(np.max(probabilities[idx]))
                cat = self.categories.get(int(predictions[idx]), f"Category_{predictions[idx]}")
                attack_flow_confs.append((conf, f, cat))
            attack_flow_confs.sort(key=lambda x: x[0], reverse=True)
            for conf, f, cat in attack_flow_confs[:10]:
                top_attack_flows.append({
                    "src": f"{f['src_ip']}:{f['src_port']}",
                    "dst": f"{f['dst_ip']}:{f['dst_port']}",
                    "protocol": f["protocol"],
                    "packets": f["fwd_packets"] + f["bwd_packets"],
                    "category": cat,
                    "confidence": round(conf, 4),
                })

        result = {
            "engine": "supervised",
            "available": True,
            "model": "HistGradientBoosting",
            "metrics": self.metrics,
            "total_flows": total_count,
            "attack_flows": attack_count,
            "attack_flow_ratio": round(attack_ratio, 4),
            "is_attack": is_attack,
            "confidence": round(avg_confidence, 4),
            "attack_threshold": self.ATTACK_FLOW_RATIO_THRESHOLD,
            "category_distribution": category_counts,
            "top_attack_flows": top_attack_flows,
            "aggregate_alert": aggregate_alert,
        }
        logger.info(
            f"监督检测完成 | 总流={total_count} 攻击流={attack_count} "
            f"比例={attack_ratio:.2%} 判定={'攻击' if is_attack else '正常'} "
            f"置信度={avg_confidence:.2f}"
        )
        return result

    @staticmethod
    def _aggregate_detection(packets: List[PacketInfo], flows: List[Dict]) -> Dict[str, Any]:
        """
        PCAP 级聚合检测：识别流级模型无法捕捉的攻击模式
        （如 SYN flood、端口扫描、RST storm 等单包流攻击）
        """
        if not packets or not flows:
            return {"triggered": False, "reason": "无数据"}

        total_pkts = len(packets)
        total_flows = len(flows)

        # 单包流比例
        single_pkt_flows = sum(1 for f in flows if (f["fwd_packets"] + f["bwd_packets"]) <= 1)
        single_pkt_ratio = single_pkt_flows / total_flows if total_flows > 0 else 0.0

        # 标志位统计
        syn_count = sum(1 for p in packets if "SYN" in (p.flags or ""))
        ack_count = sum(1 for p in packets if "ACK" in (p.flags or ""))
        rst_count = sum(1 for p in packets if "RST" in (p.flags or ""))
        syn_ratio = syn_count / total_pkts if total_pkts > 0 else 0.0
        rst_ratio = rst_count / total_pkts if total_pkts > 0 else 0.0

        # 端口多样性
        dst_ports = set(f["dst_port"] for f in flows)
        src_ports = set(f["src_port"] for f in flows)
        dst_port_count = len(dst_ports)

        # 包/流比例（平均每流包数）
        pkts_per_flow = total_pkts / total_flows if total_flows > 0 else 0.0

        alerts = []

        # SYN flood：大量单包 SYN 流
        if (single_pkt_ratio > 0.7 and syn_ratio > 0.5
                and pkts_per_flow < 3 and total_flows >= 20):
            alerts.append({
                "type": "SYN_FLOOD",
                "confidence": 0.9,
                "evidence": f"单包流比例={single_pkt_ratio:.1%}, SYN比例={syn_ratio:.1%}, "
                            f"流数={total_flows}, 平均每流包数={pkts_per_flow:.1f}",
            })

        # 端口扫描：大量单包流，目的端口多样
        if (single_pkt_ratio > 0.6 and dst_port_count >= 20
                and pkts_per_flow < 3 and total_flows >= 20):
            alerts.append({
                "type": "PORT_SCAN",
                "confidence": 0.85,
                "evidence": f"单包流比例={single_pkt_ratio:.1%}, 目的端口数={dst_port_count}, "
                            f"流数={total_flows}",
            })

        # RST storm：大量 RST 包
        if rst_ratio > 0.5 and total_pkts >= 20:
            alerts.append({
                "type": "RST_STORM",
                "confidence": 0.85,
                "evidence": f"RST比例={rst_ratio:.1%}, 总包数={total_pkts}",
            })

        # DNS 隧道：大量 DNS 查询，包长异常
        dns_pkts = [p for p in packets if p.protocol == "DNS" or p.dst_port == 53 or p.src_port == 53]
        if len(dns_pkts) >= 10:
            avg_dns_len = sum(p.length for p in dns_pkts) / len(dns_pkts)
            if avg_dns_len > 200:
                alerts.append({
                    "type": "DNS_TUNNEL",
                    "confidence": 0.75,
                    "evidence": f"DNS包数={len(dns_pkts)}, 平均包长={avg_dns_len:.0f}",
                })

        return {
            "triggered": len(alerts) > 0,
            "alerts": alerts,
            "stats": {
                "single_pkt_ratio": round(single_pkt_ratio, 4),
                "syn_ratio": round(syn_ratio, 4),
                "rst_ratio": round(rst_ratio, 4),
                "dst_port_count": dst_port_count,
                "pkts_per_flow": round(pkts_per_flow, 2),
            },
        }

    @staticmethod
    def adaptive_thresholds(packets: List[PacketInfo]) -> Dict[str, float]:
        """
        自适应阈值引擎（P0-2 B）：根据输入流量的分位数动态调整规则阈值。
        解决固定阈值在不同流量分布下召回率低的问题（如 UNSW 匿名化数据）。
        :return: 自适应阈值字典
        """
        if not packets:
            return {}
        total = len(packets)
        # 每源IP的SYN数
        syn_by_src = defaultdict(int)
        for p in packets:
            if "SYN" in (p.flags or "") and "ACK" not in (p.flags or ""):
                syn_by_src[p.src_ip] += 1
        syn_counts = sorted(syn_by_src.values(), reverse=True)
        # 每源IP的目的端口数
        ports_by_src = defaultdict(set)
        for p in packets:
            if p.src_ip and p.dst_port > 0:
                ports_by_src[p.src_ip].add(p.dst_port)
        port_counts = sorted([len(v) for v in ports_by_src.values()], reverse=True)

        def percentile(arr, pct):
            if not arr:
                return 0
            k = max(0, min(len(arr) - 1, int(len(arr) * pct / 100)))
            return arr[k]

        return {
            "syn_flood_threshold": max(50, percentile(syn_counts, 95) * 2),
            "port_scan_threshold": max(10, percentile(port_counts, 95) * 2),
            "rst_storm_threshold": max(30, int(total * 0.3)),
            "large_flow_mb": max(5.0, 10.0),
            "adaptive_note": "基于输入流量 P95 分位数动态调整，适应不同流量分布",
        }

    @staticmethod
    def ensemble_vote(supervised_result: Dict, rule_alerts: List,
                      baseline_result: Optional[Dict],
                      isolation_result: Optional[Dict]) -> Dict[str, Any]:
        """
        多模型集成投票（P0-2 C）：综合监督模型、规则引擎、基线、孤立森林的结果。
        加权投票：监督模型权重 0.5，规则 0.2，基线 0.15，孤立森林 0.15。
        :return: 集成判定结果
        """
        votes = []
        weights = []

        # 监督模型
        if supervised_result and supervised_result.get("available"):
            votes.append(1.0 if supervised_result.get("is_attack") else 0.0)
            weights.append(0.5)

        # 规则引擎
        rule_attack = len(rule_alerts) > 0
        votes.append(1.0 if rule_attack else 0.0)
        weights.append(0.2)

        # 基线
        if baseline_result and baseline_result.get("detected"):
            votes.append(1.0)
            weights.append(0.15)
        elif baseline_result is not None:
            votes.append(0.0)
            weights.append(0.15)

        # 孤立森林
        if isolation_result and isolation_result.get("anomaly_windows", 0) > 0:
            votes.append(1.0)
            weights.append(0.15)
        elif isolation_result is not None:
            votes.append(0.0)
            weights.append(0.15)

        if not votes:
            return {"is_attack": False, "confidence": 0.0, "votes": [], "method": "none"}

        total_weight = sum(weights)
        weighted_score = sum(v * w for v, w in zip(votes, weights)) / total_weight
        is_attack = weighted_score >= 0.5

        return {
            "is_attack": is_attack,
            "confidence": round(weighted_score, 4),
            "weighted_score": round(weighted_score, 4),
            "votes": [
                {"engine": "supervised", "vote": votes[0] if len(votes) > 0 else None,
                 "weight": 0.5},
                {"engine": "rules", "vote": votes[1] if len(votes) > 1 else None,
                 "weight": 0.2},
                {"engine": "baseline", "vote": votes[2] if len(votes) > 2 else None,
                 "weight": 0.15},
                {"engine": "isolation_forest", "vote": votes[3] if len(votes) > 3 else None,
                 "weight": 0.15},
            ],
            "method": "weighted_voting",
            "threshold": 0.5,
        }
