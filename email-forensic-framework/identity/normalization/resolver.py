"""
Identity Normalization & Alias Resolver.
Resolves disparate user identifiers (UPNs, sAMAccountNames, employee IDs, email aliases) into canonical Identity IDs.
"""
from typing import Dict, List, Optional, Set
import re


class IdentityResolver:
    """Resolves arbitrary identity handles into canonical Identity IDs."""

    def __init__(self):
        # Alias handle -> Canonical identity_id
        self._aliases: Dict[str, str] = {
            "john.smith": "ID-1192",
            "jsmith": "ID-1192",
            "john.smith@enterprise.org": "ID-1192",
            "emp-1192": "ID-1192",
            "alice.chen": "ID-2044",
            "achen": "ID-2044",
            "alice.chen@enterprise.org": "ID-2044",
            "emp-2044": "ID-2044",
            "bob.contractor": "ID-3088",
            "bcontractor@external-vendor.com": "ID-3088",
            "emp-3088": "ID-3088",
            "svc-mta": "ID-SERVICE-MTA",
            "svc-mta-pipeline": "ID-SERVICE-MTA",
            "mta-relay": "ID-SERVICE-MTA",
        }

    def register_alias(self, alias: str, canonical_id: str) -> None:
        self._aliases[alias.strip().lower()] = canonical_id

    def resolve(self, handle_or_email: str) -> str:
        """
        Resolves handle to canonical identity_id.
        If already a valid ID or unknown, returns normalized canonical or raw ID.
        """
        clean = handle_or_email.strip().lower()
        if clean in self._aliases:
            return self._aliases[clean]

        # Check if already in canonical ID format (e.g., ID-XXXX)
        if clean.startswith("id-"):
            return clean.upper()

        return handle_or_email.strip()

    def get_aliases_for_identity(self, canonical_id: str) -> List[str]:
        return [alias for alias, c_id in self._aliases.items() if c_id.upper() == canonical_id.upper()]
