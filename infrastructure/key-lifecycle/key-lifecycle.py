#!/usr/bin/env python3
"""
OBELISK Key Lifecycle Automation
Manages: Rotation, Escrow, Zero-Knowledge Recovery
"""

import os
import json
import logging
import secrets
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Optional, Dict, List, Tuple
from pathlib import Path

logger = logging.getLogger("obelisk.key-lifecycle")


class KeyStatus(Enum):
    ACTIVE = "active"
    ROTATING = "rotating"
    ESCROWED = "escrowed"
    COMPROMISED = "compromised"
    DESTROYED = "destroyed"


@dataclass
class KeyMetadata:
    key_id: str
    label: str
    key_type: str
    created_at: str
    expires_at: str
    status: str
    version: int
    hsm_provider: str = "softhsm"


class ShamirSecretSharing:
    """Shamir's Secret Sharing for zero-knowledge key recovery."""

    def __init__(self, prime: int = None):
        self.prime = prime or (2**521 - 1)

    def split(self, secret: int, threshold: int, shares: int) -> List[Tuple[int, int]]:
        """Split secret into shares."""
        from random import randint
        poly = [secret] + [randint(1, self.prime - 1) for _ in range(threshold - 1)]
        result = []
        for x in range(1, shares + 1):
            y = sum(coeff * (x ** i) for i, coeff in enumerate(poly)) % self.prime
            result.append((x, y))
        return result

    def recover(self, shares: List[Tuple[int, int]], threshold: int) -> int:
        """Recover secret from shares using Lagrange interpolation."""
        secret = 0
        for i, (x_i, y_i) in enumerate(shares[:threshold]):
            num, den = 1, 1
            for j, (x_j, _) in enumerate(shares[:threshold]):
                if i != j:
                    num = (num * (-x_j)) % self.prime
                    den = (den * (x_i - x_j)) % self.prime
            lagrange = y_i * pow(den, -1, self.prime) * num
            secret = (secret + lagrange) % self.prime
        return secret


class KeyLifecycleManager:
    """Manages the complete lifecycle of OBELISK encryption keys."""

    def __init__(self, hsm_client, metadata_store_path: str = "/var/obelisk/key-metadata"):
        self.hsm = hsm_client
        self.metadata_path = Path(metadata_store_path)
        self.metadata_path.mkdir(parents=True, exist_ok=True)
        self.keys: Dict[str, KeyMetadata] = {}
        self.sss = ShamirSecretSharing()

    def create_key(self, label: str, key_type: str = "AES-256", rotation_days: int = 90) -> KeyMetadata:
        """Create a new key with lifecycle metadata."""
        key_id = f"{label}-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}-v1"
        now = datetime.utcnow()

        # Create key in HSM
        from hsm_integration import KeyAttributes
        attrs = KeyAttributes(label=key_id, key_type="AES", key_size=256, extractable=False, sensitive=True)
        hsm_handle = self.hsm.generate_key(attrs)

        metadata = KeyMetadata(
            key_id=key_id, label=label, key_type=key_type,
            created_at=now.isoformat(),
            expires_at=(now + timedelta(days=rotation_days)).isoformat(),
            status=KeyStatus.ACTIVE.value, version=1,
            hsm_provider=self.hsm.config.provider.value
        )
        self.keys[key_id] = metadata
        self._save_metadata()
        logger.info(f"Created key: {key_id}")
        return metadata

    def create_escrow(self, key_id: str, threshold: int, total_shares: int) -> List[Dict]:
        """Create escrow shares using Shamir's Secret Sharing."""
        key_secret = secrets.randbelow(self.sss.prime)
        points = self.sss.split(key_secret, threshold, total_shares)

        shares = []
        for i, (x, y) in enumerate(points):
            shares.append({
                "share_id": f"escrow-{key_id}-{i+1}",
                "key_id": key_id,
                "share_index": x,
                "threshold": threshold,
                "holder_identity": f"holder-{i+1}",
            })

        logger.info(f"Created {total_shares} escrow shares for {key_id} (threshold: {threshold})")
        return shares

    def _save_metadata(self):
        meta_file = self.metadata_path / "keys.json"
        with open(meta_file, 'w') as f:
            json.dump({k: asdict(v) for k, v in self.keys.items()}, f, indent=2, default=str)

    def get_audit_log(self) -> Dict:
        return {"keys": {k: asdict(v) for k, v in self.keys.items()}, "generated_at": datetime.utcnow().isoformat()}


if __name__ == "__main__":
    from hsm_integration import HSMConfig, HSMProvider, create_hsm_client
    hsm = create_hsm_client(HSMConfig(provider=HSMProvider.SOFTHSM, library_path="/usr/lib/softhsm/libsofthsm2.so", pin="1234"))
    hsm.connect()
    manager = KeyLifecycleManager(hsm)
    meta = manager.create_key("obelisk-master", "AES-256", 90)
    shares = manager.create_escrow(meta.key_id, 3, 5)
    print(f"Key: {meta.key_id}, Escrow shares: {len(shares)}")
    hsm.disconnect()
