#!/usr/bin/env python3
"""
OBELISK License Enforcement Layer
API key validation, seat counting, feature gating
Supports: Developer, Team, Enterprise, Critical Infrastructure tiers
"""

import hashlib
import hmac
import json
import time
import secrets
import logging
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, List, Set
from dataclasses import dataclass, asdict

logger = logging.getLogger("obelisk.license")


class LicenseTier(Enum):
    DEVELOPER = "developer"
    TEAM = "team"
    ENTERPRISE = "enterprise"
    CRITICAL_INFRASTRUCTURE = "critical"


class Feature(Enum):
    VAULT_ACCESS = "vault_access"
    PDDL_ENGINES = "pddl_engines"
    HSM_SOFT = "hsm_soft"
    HSM_CLOUD = "hsm_cloud"
    HSM_DEDICATED = "hsm_dedicated"
    HEALTHCARE_DOMAINS = "healthcare_domains"
    FINANCE_DOMAINS = "finance_domains"
    DEFENSE_DOMAINS = "defense_domains"
    CUSTOM_PDDL = "custom_pddl"
    MARKETPLACE_ACCESS = "marketplace_access"
    BASIC_AUDIT = "basic_audit"
    ADVANCED_AUDIT = "advanced_audit"
    REAL_TIME_MONITORING = "real_time_monitoring"
    CISO_DASHBOARD = "ciso_dashboard"
    COMPLIANCE_TEMPLATES = "compliance_templates"
    SSO_SAML = "sso_saml"
    SSO_OIDC = "sso_oidc"
    BASIC_TESTS = "basic_tests"
    ADVANCED_TESTS = "advanced_tests"
    CUSTOM_ADVERSARIAL = "custom_adversarial"
    COMMUNITY_SUPPORT = "community_support"
    EMAIL_SUPPORT = "email_support"
    PHONE_SUPPORT = "phone_support"
    DEDICATED_CSM = "dedicated_csm"


TIER_FEATURES: Dict[LicenseTier, Set[Feature]] = {
    LicenseTier.DEVELOPER: {
        Feature.VAULT_ACCESS, Feature.PDDL_ENGINES, Feature.HSM_SOFT,
        Feature.HEALTHCARE_DOMAINS, Feature.BASIC_AUDIT,
        Feature.BASIC_TESTS, Feature.COMMUNITY_SUPPORT,
    },
    LicenseTier.TEAM: {
        Feature.VAULT_ACCESS, Feature.PDDL_ENGINES, Feature.HSM_SOFT,
        Feature.HEALTHCARE_DOMAINS, Feature.FINANCE_DOMAINS, Feature.DEFENSE_DOMAINS,
        Feature.ADVANCED_AUDIT, Feature.REAL_TIME_MONITORING, Feature.CISO_DASHBOARD,
        Feature.COMPLIANCE_TEMPLATES, Feature.BASIC_TESTS, Feature.ADVANCED_TESTS,
        Feature.EMAIL_SUPPORT,
    },
    LicenseTier.ENTERPRISE: {
        Feature.VAULT_ACCESS, Feature.PDDL_ENGINES, Feature.HSM_CLOUD, Feature.HSM_DEDICATED,
        Feature.HEALTHCARE_DOMAINS, Feature.FINANCE_DOMAINS, Feature.DEFENSE_DOMAINS,
        Feature.CUSTOM_PDDL, Feature.MARKETPLACE_ACCESS,
        Feature.ADVANCED_AUDIT, Feature.REAL_TIME_MONITORING, Feature.CISO_DASHBOARD,
        Feature.COMPLIANCE_TEMPLATES, Feature.SSO_SAML, Feature.SSO_OIDC,
        Feature.BASIC_TESTS, Feature.ADVANCED_TESTS, Feature.CUSTOM_ADVERSARIAL,
        Feature.PHONE_SUPPORT,
    },
    LicenseTier.CRITICAL_INFRASTRUCTURE: {
        Feature.VAULT_ACCESS, Feature.PDDL_ENGINES, Feature.HSM_DEDICATED,
        Feature.HEALTHCARE_DOMAINS, Feature.FINANCE_DOMAINS, Feature.DEFENSE_DOMAINS,
        Feature.CUSTOM_PDDL, Feature.MARKETPLACE_ACCESS,
        Feature.ADVANCED_AUDIT, Feature.REAL_TIME_MONITORING, Feature.CISO_DASHBOARD,
        Feature.COMPLIANCE_TEMPLATES, Feature.SSO_SAML, Feature.SSO_OIDC,
        Feature.BASIC_TESTS, Feature.ADVANCED_TESTS, Feature.CUSTOM_ADVERSARIAL,
        Feature.PHONE_SUPPORT, Feature.DEDICATED_CSM,
    },
}

TIER_LIMITS = {
    LicenseTier.DEVELOPER: {"max_agents": 2, "max_vaults": 1, "audit_retention_days": 7},
    LicenseTier.TEAM: {"max_agents": 20, "max_vaults": 10, "audit_retention_days": 90},
    LicenseTier.ENTERPRISE: {"max_agents": 999999, "max_vaults": 999999, "audit_retention_days": 365},
    LicenseTier.CRITICAL_INFRASTRUCTURE: {"max_agents": 999999, "max_vaults": 999999, "audit_retention_days": 2555},
}


@dataclass
class LicenseKey:
    key_id: str
    tier: LicenseTier
    organization: str
    issued_at: datetime
    expires_at: datetime
    max_seats: int
    features: List[str]
    signature: str

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def to_dict(self) -> dict:
        return {
            "key_id": self.key_id,
            "tier": self.tier.value,
            "organization": self.organization,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "max_seats": self.max_seats,
            "features": self.features,
        }


class LicenseManager:
    """Manages OBELISK license validation and enforcement."""

    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self._active_licenses: Dict[str, LicenseKey] = {}
        self._seat_usage: Dict[str, int] = {}

    def generate_license(self, tier: LicenseTier, organization: str, duration_days: int = 365) -> LicenseKey:
        key_id = f"OBK-{secrets.token_hex(8).upper()}"
        now = datetime.utcnow()
        seats = TIER_LIMITS[tier]["max_agents"]
        features = [f.value for f in TIER_FEATURES[tier]]

        license_data = {
            "key_id": key_id, "tier": tier.value, "organization": organization,
            "issued_at": now.isoformat(),
            "expires_at": (now + timedelta(days=duration_days)).isoformat(),
            "max_seats": seats, "features": features,
        }
        signature = self._sign_license(license_data)

        license_key = LicenseKey(
            key_id=key_id, tier=tier, organization=organization,
            issued_at=now, expires_at=now + timedelta(days=duration_days),
            max_seats=seats, features=features, signature=signature,
        )
        self._active_licenses[key_id] = license_key
        logger.info(f"Generated {tier.value} license: {key_id}")
        return license_key

    def _sign_license(self, data: dict) -> str:
        payload = json.dumps(data, sort_keys=True)
        return hmac.new(self.secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()

    def validate_license(self, key_id: str) -> bool:
        if key_id not in self._active_licenses:
            return False
        license_key = self._active_licenses[key_id]
        if license_key.is_expired():
            return False
        expected_sig = self._sign_license(license_key.to_dict())
        return hmac.compare_digest(license_key.signature, expected_sig)

    def check_feature(self, key_id: str, feature: Feature) -> bool:
        if not self.validate_license(key_id):
            return False
        return feature.value in self._active_licenses[key_id].features

    def get_usage_report(self, key_id: str) -> dict:
        if key_id not in self._active_licenses:
            return {"error": "License not found"}
        lk = self._active_licenses[key_id]
        seats_used = self._seat_usage.get(key_id, 0)
        return {
            "license_id": key_id, "tier": lk.tier.value,
            "organization": lk.organization,
            "expires_at": lk.expires_at.isoformat(),
            "days_remaining": (lk.expires_at - datetime.utcnow()).days,
            "seats": {"used": seats_used, "total": lk.max_seats, "available": lk.max_seats - seats_used},
            "features": lk.features,
        }


if __name__ == "__main__":
    manager = LicenseManager("obelisk-dev-secret-key")
    key = manager.generate_license(LicenseTier.TEAM, "ACME Corp", 365)
    print(f"License: {key.key_id}")
    print(f"Valid: {manager.validate_license(key.key_id)}")
    print(f"Has CISO Dashboard: {manager.check_feature(key.key_id, Feature.CISO_DASHBOARD)}")
    print(json.dumps(manager.get_usage_report(key.key_id), indent=2))
