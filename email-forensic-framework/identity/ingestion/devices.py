"""
Device Identity Ingestion.
Tracks physical laptops, mobile devices, servers, and virtual machines in the enterprise fleet.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import Enum
import time


class DeviceType(str, Enum):
    LAPTOP = "LAPTOP"
    WORKSTATION = "WORKSTATION"
    SERVER = "SERVER"
    MOBILE = "MOBILE"
    SECURITY_GATEWAY = "SECURITY_GATEWAY"
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"


class DeviceComplianceStatus(str, Enum):
    COMPLIANT = "COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    UNKNOWN = "UNKNOWN"
    QUARANTINED = "QUARANTINED"


@dataclass
class DeviceIdentity:
    device_id: str
    hostname: str
    serial_number: str
    owner_identity_id: str
    device_type: DeviceType
    operating_system: str
    os_version: str
    managed: bool
    compliance_status: DeviceComplianceStatus = DeviceComplianceStatus.COMPLIANT
    certificate_serial: Optional[str] = None
    mac_address: Optional[str] = None
    last_seen_ip: Optional[str] = None
    network_location: str = "CORPORATE_SECURE_VPC"
    enrolled_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "device_id": self.device_id,
            "hostname": self.hostname,
            "serial_number": self.serial_number,
            "owner_identity_id": self.owner_identity_id,
            "device_type": self.device_type.value if isinstance(self.device_type, DeviceType) else self.device_type,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "managed": self.managed,
            "compliance_status": self.compliance_status.value if isinstance(self.compliance_status, DeviceComplianceStatus) else self.compliance_status,
            "certificate_serial": self.certificate_serial,
            "network_location": self.network_location,
            "last_seen_ip": self.last_seen_ip,
        }


class DeviceIdentityRepository:
    """Registry of device identities."""

    def __init__(self):
        self._devices: Dict[str, DeviceIdentity] = {}
        self._load_defaults()

    def _load_defaults(self):
        defaults = [
            DeviceIdentity(
                device_id="DEVICE-44",
                hostname="soc-laptop-44.corp.local",
                serial_number="SN-CORP-99210-44",
                owner_identity_id="ID-1192",
                device_type=DeviceType.LAPTOP,
                operating_system="macOS",
                os_version="15.2",
                managed=True,
                compliance_status=DeviceComplianceStatus.COMPLIANT,
                certificate_serial="CERT-DEV-44-CORP",
                last_seen_ip="10.200.1.44",
                network_location="SOC_SECURE_SUBNET",
            ),
            DeviceIdentity(
                device_id="DEVICE-91",
                hostname="infra-box-91.corp.local",
                serial_number="SN-CORP-88112-91",
                owner_identity_id="ID-2044",
                device_type=DeviceType.WORKSTATION,
                operating_system="Ubuntu-Linux",
                os_version="24.04-LTS",
                managed=True,
                compliance_status=DeviceComplianceStatus.COMPLIANT,
                certificate_serial="CERT-DEV-91-CORP",
                last_seen_ip="10.200.1.91",
                network_location="ENG_MGMT_VLAN",
            ),
            DeviceIdentity(
                device_id="DEVICE-UNMANAGED-77",
                hostname="bobs-personal-macbook.local",
                serial_number="SN-PERSONAL-33881",
                owner_identity_id="ID-3088",
                device_type=DeviceType.LAPTOP,
                operating_system="macOS",
                os_version="14.1",
                managed=False,
                compliance_status=DeviceComplianceStatus.NON_COMPLIANT,
                certificate_serial=None,
                last_seen_ip="192.168.10.88",
                network_location="GUEST_WIFI",
            ),
        ]
        for d in defaults:
            self._devices[d.device_id] = d

    def get(self, device_id: str) -> Optional[DeviceIdentity]:
        return self._devices.get(device_id)

    def list_all(self) -> List[DeviceIdentity]:
        return list(self._devices.values())

    def register(self, device: DeviceIdentity) -> None:
        self._devices[device.device_id] = device
