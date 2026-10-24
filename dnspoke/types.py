"""Typed data exchanged between the store, clients, and DNS adapters."""
from typing import NotRequired, Protocol, TypedDict

class Enrollment(TypedDict):
    device_id: str
    device_secret: str
    hostname: str


class UpdateToken(TypedDict):
    token: str
    expires_in: int
    hostname: str


class DeviceConfig(TypedDict):
    server: str
    hostname: str
    device_secret: str
    device_id: NotRequired[str]
    last_ip: NotRequired[str]
    last_sync: NotRequired[float]
    check_period_minutes: NotRequired[int]
    ip_mode: NotRequired[str]


class DNSRecord(TypedDict):
    id: str
    name: str
    type: str
    content: str
    ttl: NotRequired[int]


class DNSProvider(Protocol):
    def update(self, name: str, ip: str, adopt: bool) -> bool: ...


class RecordClient(Protocol):
    def list_records(self) -> list[DNSRecord]: ...
    def update_record(self, *, identifier: str, rtype: str, name: str, content: str) -> bool: ...
    def create_record(self, rtype: str, name: str, content: str, /) -> bool: ...
