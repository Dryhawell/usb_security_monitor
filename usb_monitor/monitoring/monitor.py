"""USBMonitor: connect/disconnect detection over an EventSource.

Detection stays in the event source. Normalization produces USBEvent
records. Metadata collection fills OS-exposed properties. Inventory
tracks first-seen vs known. The analyzer attaches an explainable
heuristic score and session-window anomaly counts. AlertManager turns
those findings into de-duplicated session alerts. EventStore and
AlertStore persist records as local JSON. None of this decides that a
device is malicious.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from collections.abc import Callable

from usb_monitor.alerts import AlertManager, attach_decision
from usb_monitor.analysis import Analyzer, apply_assessment, should_emit_suspicious
from usb_monitor.inventory import DeviceInventory
from usb_monitor.models.enums import EventType
from usb_monitor.models.event import USBEvent
from usb_monitor.monitoring.event_source import EventSource, RawDeviceEvent
from usb_monitor.monitoring.metadata import (
    MetadataCollector,
    NullMetadataCollector,
    apply_metadata,
)
from usb_monitor.monitoring.normalizer import EventNormalizer
from usb_monitor.storage import EventStore
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
        alerts: AlertManager | None = None,
        event_store: EventStore | None = None,
    ) -> None:
        self._source = source
        self._normalizer = normalizer or EventNormalizer(clock=time.monotonic)
        self._collector = collector or NullMetadataCollector()
        self._inventory = inventory
        self._analyzer = analyzer or Analyzer()
        self._alerts = alerts if alerts is not None else AlertManager()
        self._event_store = event_store
        self._pending: deque[USBEvent] = deque()
        self._lock = threading.Lock()
        self._log = get_logger("monitoring.usb")

    @property
    def alerts(self) -> AlertManager:
        return self._alerts

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
        except Exception:
            self._log.exception("Failed while flushing coalesced events during stop")
        try:
            self._source.stop(timeout=timeout)
        except Exception:
            self._log.exception("Event source stop failed")
        self._log.info("USB monitor stopped")

    def __enter__(self) -> USBMonitor:
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()

    def run(
        self,
        timeout: float,
        *,
        on_event: Callable[[USBEvent], None] | None = None,
        stop_when: Callable[[], bool] | None = None,
    ) -> int:
        """Poll until ``timeout`` seconds elapse. Isolates per-event failures.

        Starts the source if it is idle. When this method started the source,
        it also stops it. A surrounding context manager still owns shutdown
        if the source was already running. KeyboardInterrupt is not swallowed.
        """
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        started_here = False
        if not self.is_running:
            self.start()
            started_here = True
        seen = 0
        deadline = time.monotonic() + timeout
        try:
            while True:
                if stop_when is not None and stop_when():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                try:
                    event = self.poll(timeout=min(_POLL_SLICE, remaining))
                except Exception:
                    self._log.exception("Poll failed; continuing")
                    continue
                if event is None:
                    continue
                seen += 1
                self._deliver(event, on_event)
        finally:
            if started_here:
                self.stop()
            else:
                try:
                    for event in self._normalizer.flush_all():
                        self._queue_event(event)
                except Exception:
                    self._log.exception("Failed while flushing coalesced events")
            leftover = self.drain()
            for event in leftover:
                seen += 1
                self._deliver(event, on_event)
        return seen

    def poll(self, timeout: float | None = None) -> USBEvent | None:
        """Return the next logical USB event, or ``None`` if the timeout expires."""
        pending = self._pop_pending()
        if pending is not None:
            return pending

        if timeout is None:
            return self._wait_for_event(None)

        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        return self._wait_for_event(timeout)

    def drain(self) -> list[USBEvent]:
        """Return any coalesced events waiting in the local buffer."""
        try:
            for event in self._normalizer.flush_ready():
                self._queue_event(event)
        except Exception:
            self._log.exception("Failed while flushing ready bursts")
        with self._lock:
            events = list(self._pending)
            self._pending.clear()
            return events

    def feed(self, raw: RawDeviceEvent) -> None:
        """Ingest one raw OS notification without polling the event source.

        Tests and replay use this so a FakeClock can close the quiet
        window. It does not open or execute USB files.
        """
        try:
            produced = self._normalizer.ingest(raw)
        except Exception:
            self._log.exception("Normalizer failed; dropping one raw notification")
            return
        for event in produced:
            self._queue_event(event)

    def replay(self) -> list[USBEvent]:
        """Pull queued mock events into the pipeline, then flush ready bursts."""
        if hasattr(self._source, "take_all"):
            queued = self._source.take_all()
        else:
            queued = []
            while True:
                try:
                    raw = self._source.poll(timeout=0)
                except Exception:
                    self._log.exception("Event source poll failed during replay")
                    break
                if raw is None:
                    break
                queued.append(raw)
        for raw in queued:
            self.feed(raw)
        return self.drain()

    def _deliver(
        self,
        event: USBEvent,
        on_event: Callable[[USBEvent], None] | None,
    ) -> None:
        if on_event is None:
            return
        try:
            on_event(event)
        except Exception:
            self._log.exception("Event callback failed; continuing")

    def _pop_pending(self) -> USBEvent | None:
        with self._lock:
            if self._pending:
                return self._pending.popleft()
        return None

    def _queue_event(self, event: USBEvent) -> None:
        metadata = NullMetadataCollector().collect(event)
        try:
            metadata = self._collector.collect(event)
        except Exception:
            self._log.exception("Metadata collection failed; using known fields only")
        try:
            apply_metadata(event, metadata)
        except Exception:
            self._log.exception("Metadata apply failed")
        observation = None
        try:
            if self._inventory is not None:
                observation = self._inventory.observe(event)
        except Exception:
            self._log.exception("Inventory update failed; event still recorded")
        assessment = None
        try:
            assessment = self._analyzer.analyze(event, observation)
            if (
                observation is not None
                and observation.derived_event is not None
                and isinstance(event.details.get("anomaly"), dict)
            ):
                observation.derived_event.details["anomaly"] = dict(event.details["anomaly"])
        except Exception:
            self._log.exception("Analysis failed; emitting without a heuristic score")
        if assessment is not None:
            try:
                apply_assessment(event, assessment)
                if self._inventory is not None and observation is not None:
                    self._inventory.update_risk(
                        observation.device.device_id,
                        assessment.score,
                        assessment.level,
                    )
                if observation is not None and observation.derived_event is not None:
                    apply_assessment(observation.derived_event, assessment)
                decision = self._alerts.consider(event, assessment)
                attach_decision(event, decision)
                if observation is not None and observation.derived_event is not None:
                    attach_decision(observation.derived_event, decision)
                if decision.alert is not None:
                    self._log.info("%s", decision.alert)
            except Exception:
                self._log.exception("Could not attach assessment or alerts")
        self._emit(event)
        if observation is not None and observation.derived_event is not None:
            self._emit(observation.derived_event)
        if assessment is not None:
            try:
                if should_emit_suspicious(assessment):
                    self._emit(_suspicious_from(event))
            except Exception:
                self._log.exception("Could not emit SUSPICIOUS_DEVICE")

    def _emit(self, event: USBEvent) -> None:
        with self._lock:
            self._pending.append(event)
        try:
            self._log.info("%s", event)
            if self._event_store is not None:
                self._event_store.append(event)
        except Exception:
            self._log.exception(
                "Could not persist %s; live stream still has the event",
                event.event_type.value,
            )

    def _wait_for_event(self, timeout: float | None) -> USBEvent | None:
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            pending = self._pop_pending()
            if pending is not None:
                return pending

            remaining: float | None
            if deadline is None:
                remaining = _POLL_SLICE
            else:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    try:
                        for event in self._normalizer.flush_ready():
                            self._queue_event(event)
                    except Exception:
                        self._log.exception("Failed while flushing ready bursts")
                    return self._pop_pending()

            try:
                raw = self._source.poll(timeout=min(_POLL_SLICE, remaining))
            except Exception:
                self._log.exception("Event source poll failed; continuing")
                raw = None
            if raw is None:
                try:
                    for event in self._normalizer.flush_ready():
                        self._queue_event(event)
                except Exception:
                    self._log.exception("Failed while flushing ready bursts")
                continue

            try:
                produced = self._normalizer.ingest(raw)
            except Exception:
                self._log.exception("Normalizer failed; dropping one raw notification")
                continue
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
