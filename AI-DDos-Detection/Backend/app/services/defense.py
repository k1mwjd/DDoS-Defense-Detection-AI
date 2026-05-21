from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import subprocess
from typing import Dict
from typing import List
from typing import Optional

from app.config import DEFAULT_BLOCK_SECONDS, DEFAULT_DEFENSE_THRESHOLD


def calculate_risk_score(attack_probability: float) -> float:
    bounded_probability = max(0.0, min(1.0, attack_probability))
    return round(bounded_probability * 100.0, 2)


def classify_risk_level(risk_score: float) -> str:
    if risk_score >= 90.0:
        return "critical"
    if risk_score >= 70.0:
        return "high"
    if risk_score >= 40.0:
        return "medium"
    return "low"


@dataclass
class DefenseDecision:
    should_block: bool
    action_taken: str
    reason: str
    risk_score: float
    risk_level: str


class DefenseManager:
    def __init__(
        self,
        threshold: float = DEFAULT_DEFENSE_THRESHOLD,
        block_seconds: int = DEFAULT_BLOCK_SECONDS,
        enable_windows_firewall: bool = False,
    ) -> None:
        self.threshold = threshold
        self.block_seconds = block_seconds
        self.enable_windows_firewall = enable_windows_firewall
        self._blocked_sources: Dict[str, datetime] = {}

    def evaluate(self, prediction: int, attack_probability: float, source_ip: Optional[str] = None) -> DefenseDecision:
        risk_score = calculate_risk_score(attack_probability)
        risk_level = classify_risk_level(risk_score)

        if prediction != 1:
            return DefenseDecision(False, "allow", "predicted_as_benign", risk_score, risk_level)
        if risk_score < self.threshold:
            return DefenseDecision(False, "monitor", "attack_probability_below_threshold", risk_score, risk_level)
        if not source_ip:
            return DefenseDecision(False, "alert_only", "source_ip_missing", risk_score, risk_level)

        normalized_ip = self._normalize_ip(source_ip)
        self._blocked_sources[normalized_ip] = datetime.now(timezone.utc) + timedelta(seconds=self.block_seconds)

        action_taken = "blocked_in_memory"
        if self.enable_windows_firewall:
            self._apply_windows_firewall_rule(normalized_ip)
            action_taken = "blocked_in_memory_and_windows_firewall"

        return DefenseDecision(True, action_taken, "attack_predicted_and_threshold_exceeded", risk_score, risk_level)

    def list_blocked_sources(self) -> List[Dict[str, str]]:
        self._purge_expired()
        return [
            {"source_ip": source_ip, "expires_at_utc": expires_at.isoformat()}
            for source_ip, expires_at in sorted(self._blocked_sources.items())
        ]

    def unblock(self, source_ip: str) -> bool:
        normalized_ip = self._normalize_ip(source_ip)
        removed = self._blocked_sources.pop(normalized_ip, None) is not None
        if removed and self.enable_windows_firewall:
            self._remove_windows_firewall_rule(normalized_ip)
        return removed

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc)
        expired_sources = [source_ip for source_ip, expires_at in self._blocked_sources.items() if expires_at <= now]
        for source_ip in expired_sources:
            self._blocked_sources.pop(source_ip, None)
            if self.enable_windows_firewall:
                self._remove_windows_firewall_rule(source_ip)

    @staticmethod
    def _normalize_ip(source_ip: str) -> str:
        return str(ipaddress.ip_address(source_ip))

    @staticmethod
    def _rule_name(source_ip: str) -> str:
        return f"AI_DDOS_BLOCK_{source_ip}"

    def _apply_windows_firewall_rule(self, source_ip: str) -> None:
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "add",
                "rule",
                f"name={self._rule_name(source_ip)}",
                "dir=in",
                "action=block",
                f"remoteip={source_ip}",
            ],
            check=True,
            capture_output=True,
            text=True,
        )

    def _remove_windows_firewall_rule(self, source_ip: str) -> None:
        subprocess.run(
            [
                "netsh",
                "advfirewall",
                "firewall",
                "delete",
                "rule",
                f"name={self._rule_name(source_ip)}",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
