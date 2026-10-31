"""Narrow Lexicon adapter: exact-name A records only; never prune other records."""

import logging
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, cast
from unittest.mock import patch

from .core import Rejected
from .types import RecordClient


class LexiconProvider:
    def __init__(self, zone: str, provider_name: str | None) -> None:
        if not isinstance(provider_name, str) or not re.fullmatch(
            r"[a-z][a-z0-9_]*", provider_name
        ):
            raise ValueError("DNS_PROVIDER must be a Lexicon provider identifier")
        self.zone = zone
        self.provider_name = provider_name

    @contextmanager
    def connect(self) -> Iterator[RecordClient]:
        import requests
        from lexicon.client import Client
        from lexicon.config import ConfigResolver

        # Lexicon does not supply timeouts for all authentication requests.
        # The production process uses a single worker/thread (no concurrent patch).
        original = requests.sessions.Session.request

        def bounded(
            session: requests.Session, method: str | bytes, url: str | bytes, **kwargs: Any
        ) -> requests.Response:
            kwargs.setdefault("timeout", 10)
            return original(session, method, url, **kwargs)

        logging.getLogger("lexicon").setLevel(logging.CRITICAL)
        # Lexicon exposes a typed resolver with an unannotated constructor.
        resolver_factory = cast(Callable[[], ConfigResolver], ConfigResolver)
        config = (
            resolver_factory()
            .with_env()
            .with_dict(
                dict_object={"provider_name": self.provider_name, "domain": self.zone, "ttl": 900}
            )
        )
        with patch.object(requests.sessions.Session, "request", bounded):
            with Client(config) as client:
                yield cast(RecordClient, client)

    def update(self, name: str, ip: str, adopt: bool) -> bool:
        with self.connect() as client:
            # Lexicon's name filter is a substring match, so filter ourselves.
            records = [r for r in client.list_records() if r["name"].rstrip(".").lower() == name]
            if len(records) > 1 or any(r["type"] != "A" for r in records):
                raise Rejected("Conflicting DNS records; ask the administrator", 409)
            old = records[0]["content"] if records else None
            if records and not adopt:
                raise Rejected("Existing DNS record needs administrator adoption", 409)
            if old == ip:
                return False
            if records:
                ok = client.update_record(
                    identifier=records[0]["id"], rtype="A", name=name, content=ip
                )
            else:
                ok = client.create_record("A", name, ip)
            if not ok:
                raise RuntimeError("DNS provider did not acknowledge update")
            after = [r for r in client.list_records() if r["name"].rstrip(".").lower() == name]
            if len(after) != 1 or after[0]["type"] != "A" or after[0]["content"] != ip:
                raise RuntimeError("DNS provider verification failed")
            return True
