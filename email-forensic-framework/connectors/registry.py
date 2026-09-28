"""
Phase 24 — Connector Registry (Component 44, 45)
Maintains active connectors and routes ActionTypes to their concrete implementations.
"""

from typing import Dict, Any, List
from response.actions import ActionType
from connectors.base import BaseResponseConnector, ConnectorHealth
from connectors.firewall import FirewallConnector
from connectors.pki import PKIConnector
from connectors.endpoint import EndpointConnector
from connectors.identity import IdentityConnector
from connectors.ticketing import TicketingConnector
from connectors.notifications import NotificationConnector


class ConnectorRegistry:
    """Central registry routing actions to specialized environment connectors."""

    def __init__(self):
        self.firewall = FirewallConnector()
        self.pki = PKIConnector()
        self.endpoint = EndpointConnector()
        self.identity = IdentityConnector()
        self.ticketing = TicketingConnector()
        self.notifications = NotificationConnector()

        self._type_map: Dict[ActionType, BaseResponseConnector] = {
            ActionType.NETWORK: self.firewall,
            ActionType.CERTIFICATE: self.pki,
            ActionType.ENDPOINT: self.endpoint,
            ActionType.CRYPTOGRAPHIC: self.endpoint,
            ActionType.IDENTITY: self.identity,
            ActionType.TICKETING: self.ticketing,
            ActionType.NOTIFICATION: self.notifications,
        }

    def get_connector_for_type(self, action_type: ActionType) -> BaseResponseConnector:
        connector = self._type_map.get(action_type)
        if not connector:
            return self.endpoint
        return connector

    def check_all_connectors_health(self) -> Dict[str, ConnectorHealth]:
        return {
            "firewall": self.firewall.health_check(),
            "pki": self.pki.health_check(),
            "endpoint": self.endpoint.health_check(),
            "identity": self.identity.health_check(),
            "ticketing": self.ticketing.health_check(),
            "notifications": self.notifications.health_check(),
        }
