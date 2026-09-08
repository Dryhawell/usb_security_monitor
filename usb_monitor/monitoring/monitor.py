"""USBMonitor: connect/disconnect detection over an EventSource.

Detection stays in the event source. Normalization produces USBEvent
records. Metadata collection fills OS-exposed properties. Inventory
tracks first-seen vs known. The analyzer attaches an explainable
heuristic score and session-window anomaly counts. It does not decide
that a device is malicious.
"""

from __future__ import annotations

import time
from collections import deque

from usb_monitor.analysis import Analyzer, apply_assessment, should_emit_suspicious
from usb_monitor.inventory import DeviceInventory
from usb_monitor.models.enums import EventType
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring.event_source import EventSource
from usb_monitor.monitoring.metadata import (
    MetadataCollector,
    NullMetadataCollector,
    apply_metadata,
)
from usb_monitor.monitoring.normalizer import EventNormalizer
from usb_monitor.utils.logger import get_logger

_POLL_SLICE = 0.2


class USBMonitor:
    """Read raw OS events and yield coalesced CONNECT/DISCONNECT USBEvents."""

    def __init__(
        self,
        source: EventSource,
        *,
        normalizer: EventNormalizer | None = None,
        collector: MetadataCollector | None = None,
        inventory: DeviceInventory | None = None,
        analyzer: Analyzer | None = None,
    ) -> None:
        self._source = source
        self._normalizer = normalizer or EventNormalizer(clock=time.monotonic)
        self._collector = collector or NullMetadataCollector()
        self._inventory = inventory
        self._analyzer = analyzer or Analyzer()
        self._pending: deque[USBEvent] = deque()
        self._log = get_logger("monitoring.usb")

    @property
    def is_running(self) -> bool:
        return self._source.is_running

    @property
    def mechanism(self) -> str:
        return self._source.mechanism

    def start(self) -> None:
        self._source.start()
        self._log.info(
            "USB monitor started (source=%s metadata=%s)",
            self.mechanism,
            self._collector.mechanism,
        )

    def stop(self, timeout: float = 5.0) -> None:
        try:
            for event in self._normalizer.flush_all():
                self._queue_event(event)
        finally:
            self._source.stop(timeout=timeout)
            self._log.info("USB monitor stopped")

    def poll(self, timeout: float | None = None) -> USBEvent | None:
        """Return the next logical USB event, or ``None`` if the timeout expires."""
        if self._pending:
            return self._pending.popleft()

        if timeout is None:
            return self._wait_for_event(None)

        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        return self._wait_for_event(timeout)

    def drain(self) -> list[USBEvent]:
        """Return any coalesced events waiting in the local buffer."""
        for event in self._normalizer.flush_ready():
            self._queue_event(event)
        events = list(self._pending)
        self._pending.clear()
        return events

    def _queue_event(self, event: USBEvent) -> None:
        try:
            metadata = self._collector.collect(event)
        except (OSError, ValueError, TypeError):
            self._log.warning("Metadata collection failed; emitting event with known fields only")
            metadata = NullMetadataCollector().collect(event)
        apply_metadata(event, metadata)
        observation = self._inventory.observe(event) if self._inventory is not None else None
        assessment = self._analyzer.analyze(event, observation)
        if (
            observation is not None
            and observation.derived_event is not None
            and isinstance(event.details.get("anomaly"), dict)
        ):
            observation.derived_event.details["anomaly"] = dict(event.details["anomaly"])
        if assessment is not None:
            apply_assessment(event, assessment)
            if self._inventory is not None and observation is not None:
                self._inventory.update_risk(
                    observation.device.device_id,
                    assessment.score,
                    assessment.level,
                )
            if observation is not None and observation.derived_event is not None:
                apply_assessment(observation.derived_event, assessment)
        self._pending.append(event)
        self._log.info("%s", event)
        if observation is not None and observation.derived_event is not None:
            self._pending.append(observation.derived_event)
            self._log.info("%s", observation.derived_event)
        if assessment is not None and should_emit_suspicious(assessment):
            suspicious = _suspicious_from(event)
            self._pending.append(suspicious)
            self._log.info("%s", suspicious)

    def _wait_for_event(self, timeout: float | None) -> USBEvent | None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if self._pending:
                return self._pending.popleft()

            remaining: float | None
            if deadline is None:
                remaining = _POLL_SLICE
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    for event in self._normalizer.flush_ready():
                        self._queue_event(event)
                    return self._pending.popleft() if self._pending else None

            raw = self._source.poll(timeout=min(_POLL_SLICE, remaining))
            if raw is None:
                for event in self._normalizer.flush_ready():
                    self._queue_event(event)
                continue

            produced = self._normalizer.ingest(raw)
            for event in produced:
                self._queue_event(event)


def _suspicious_from(event: USBEvent) -> USBEvent:
    """Copy a CONNECT into SUSPICIOUS_DEVICE when the heuristic is HIGH/CRITICAL."""
    return USBEvent(
        event_type=EventType.SUSPICIOUS_DEVICE,
        timestamp=event.timestamp,
        device_id=event.device_id,
        device_name=event.device_name,
        vendor_id=event.vendor_id,
        product_id=event.product_id,
        serial_number=event.serial_number,
        drive_letter=event.drive_letter,
        device_type=event.device_type,
        manufacturer=event.manufacturer,
        pnp_device_id=event.pnp_device_id,
        removable=event.removable,
        filesystem=event.filesystem,
        capacity=event.capacity,
        source=event.source,
        risk_score=event.risk_score,
        risk_level=event.risk_level,
        details={
            **dict(event.details),
            "from_event_id": event.event_id,
            "note": "Heuristic HIGH/CRITICAL characteristics; not a malware confirmation.",
        },
    )
