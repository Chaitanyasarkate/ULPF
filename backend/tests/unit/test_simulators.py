"""Unit tests for ULPF Phase 1 simulators."""

from __future__ import annotations

import json
import time

from ulpf.simulators.firewall import FirewallSimulator


class TestFirewallSimulator:
    def test_generated_event_is_non_empty(self):
        sim = FirewallSimulator(target_host="127.0.0.1", target_port=0)
        event = sim._run.__self__  # access internal generator via module
        from ulpf.simulators.firewall import _generate_event
        event = _generate_event()
        assert len(event) > 0

    def test_generated_event_contains_action(self):
        from ulpf.simulators.firewall import _generate_event
        event = _generate_event()
        assert any(action in event for action in ["ALLOW", "DENY", "DROP", "ACCEPT"])

    def test_generated_event_contains_ip(self):
        from ulpf.simulators.firewall import _generate_event
        event = _generate_event()
        assert "src=" in event or "10." in event

    def test_start_stop(self):
        sim = FirewallSimulator(target_host="127.0.0.1", target_port=0)
        sim.start(interval=0.1)
        time.sleep(0.3)
        sim.stop()
        assert not sim._running


class TestRouterSimulator:
    def test_generated_event_structure(self):
        from ulpf.simulators.router import _generate_event
        event = _generate_event()
        assert "timestamp" in event
        assert "src_ip" in event
        assert "dst_ip" in event
        assert "action" in event

    def test_generated_event_valid_json(self):
        from ulpf.simulators.router import _generate_event
        event = _generate_event()
        dumped = json.dumps(event)
        parsed = json.loads(dumped)
        assert parsed["src_ip"] == event["src_ip"]


class TestIDSSimulator:
    def test_generated_event_starts_with_cef(self):
        from ulpf.simulators.ids import _generate_event
        event = _generate_event()
        assert event.startswith("CEF:")

    def test_generated_event_contains_vendor(self):
        from ulpf.simulators.ids import _generate_event
        event = _generate_event()
        assert "|" in event
