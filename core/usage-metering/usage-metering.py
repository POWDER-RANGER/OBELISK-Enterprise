#!/usr/bin/env python3
"""
OBELISK Usage Metering System
Per-agent, per-vault, per-PDDL-domain consumption tracking
Integrates with Stripe for billing
"""

import json
import time
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass
from collections import defaultdict
import threading

logger = logging.getLogger("obelisk.metering")


class MeteringDimension(Enum):
    API_CALL = "api_call"
    AGENT_EXECUTION = "agent_execution"
    VAULT_ACCESS = "vault_access"
    PDDL_EVALUATION = "pddl_evaluation"
    LLM_TOKEN_INPUT = "llm_token_input"
    LLM_TOKEN_OUTPUT = "llm_token_output"
    HSM_OPERATION = "hsm_operation"
    STORAGE_GB = "storage_gb"
    BANDWIDTH_GB = "bandwidth_gb"


@dataclass
class UsageRecord:
    timestamp: float
    license_key: str
    dimension: str
    resource_id: str
    quantity: float


class UsageMeter:
    """Real-time usage metering with aggregation and alerting."""

    def __init__(self, flush_interval_seconds: int = 60):
        self._records: List[UsageRecord] = []
        self._aggregated: Dict[str, Dict] = defaultdict(lambda: defaultdict(float))
        self._lock = threading.RLock()
        self._flush_interval = flush_interval_seconds

    def record(self, license_key: str, dimension: MeteringDimension, resource_id: str, quantity: float = 1.0):
        with self._lock:
            hour_key = datetime.utcnow().strftime("%Y-%m-%d-%H")
            agg_key = f"{license_key}:{dimension.value}:{hour_key}"
            self._aggregated[agg_key]["quantity"] += quantity
            self._aggregated[agg_key]["count"] += 1
        logger.debug(f"Recorded: {dimension.value} x{quantity} for {resource_id}")

    def get_current_period_usage(self, license_key: str, dimension: MeteringDimension, period: str = "month") -> float:
        now = datetime.utcnow()
        if period == "hour": start = now.replace(minute=0, second=0, microsecond=0)
        elif period == "day": start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == "week": start = now - timedelta(days=now.weekday())
        elif period == "month": start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        else: start = now - timedelta(days=30)

        total = 0.0
        with self._lock:
            for record in self._records:
                record_time = datetime.utcfromtimestamp(record.timestamp)
                if (record.license_key == license_key and
                    record.dimension == dimension.value and
                    record_time >= start):
                    total += record.quantity
        return total

    def get_usage_report(self, license_key: str) -> Dict:
        report = {
            "license_key": license_key,
            "generated_at": datetime.utcnow().isoformat(),
            "periods": {},
        }
        for dim in MeteringDimension:
            report["periods"][dim.value] = {
                "hour": self.get_current_period_usage(license_key, dim, "hour"),
                "day": self.get_current_period_usage(license_key, dim, "day"),
                "week": self.get_current_period_usage(license_key, dim, "week"),
                "month": self.get_current_period_usage(license_key, dim, "month"),
            }
        return report

    def check_overage(self, license_key: str, limits: Dict[str, float]) -> List[Dict]:
        overages = []
        current_month = self.get_current_period_usage(license_key, MeteringDimension.API_CALL, "month")
        for limit_type, limit_value in limits.items():
            usage_pct = (current_month / limit_value) * 100 if limit_value > 0 else 0
            if usage_pct >= 100:
                overages.append({"dimension": limit_type, "limit": limit_value, "usage": current_month, "percentage": usage_pct, "severity": "critical"})
            elif usage_pct >= 80:
                overages.append({"dimension": limit_type, "limit": limit_value, "usage": current_month, "percentage": usage_pct, "severity": "warning"})
        return overages

    def export_to_stripe(self, license_key: str) -> Dict:
        stripe_records = []
        with self._lock:
            for record in self._records:
                if record.license_key == license_key:
                    stripe_records.append({"timestamp": int(record.timestamp), "action": record.dimension, "quantity": int(record.quantity)})
        return {"license_key": license_key, "record_count": len(stripe_records), "records": stripe_records}


class StripeBillingHandler:
    """Handles Stripe billing webhooks for subscription management."""

    def __init__(self, webhook_secret: str):
        self.webhook_secret = webhook_secret

    def handle_event(self, payload: str, signature: str) -> Dict:
        try:
            import stripe
            event = stripe.Webhook.construct_event(payload, signature, self.webhook_secret)
            handlers = {
                "invoice.payment_succeeded": self._handle_payment_success,
                "invoice.payment_failed": self._handle_payment_failed,
                "customer.subscription.updated": self._handle_subscription_updated,
                "customer.subscription.deleted": self._handle_subscription_deleted,
            }
            handler = handlers.get(event["type"], self._handle_unknown)
            return handler(event)
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _handle_payment_success(self, event: Dict) -> Dict:
        return {"status": "success", "action": "payment_recorded"}

    def _handle_payment_failed(self, event: Dict) -> Dict:
        return {"status": "action_required", "action": "notify_customer"}

    def _handle_subscription_updated(self, event: Dict) -> Dict:
        return {"status": "success", "action": "update_license_tier"}

    def _handle_subscription_deleted(self, event: Dict) -> Dict:
        return {"status": "success", "action": "revoke_license"}

    def _handle_unknown(self, event: Dict) -> Dict:
        return {"status": "ignored"}


if __name__ == "__main__":
    meter = UsageMeter()
    license_key = "OBK-TEST123"
    for i in range(100):
        meter.record(license_key, MeteringDimension.API_CALL, f"agent-{i % 5}")
        meter.record(license_key, MeteringDimension.LLM_TOKEN_INPUT, f"agent-{i % 5}", quantity=150)
    report = meter.get_usage_report(license_key)
    print(json.dumps(report, indent=2))
