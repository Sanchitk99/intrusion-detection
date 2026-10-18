"""Focused tests for the Live Network Flow Capture and Feature Extraction Engine."""

import unittest
from unittest.mock import MagicMock, patch
import pandas as pd
from sklearn.dummy import DummyClassifier

from scripts.flow_engine import (
    PORT_SERVICE_MAP,
    TCP_STATE_FLAG_MAP,
    FlowSession,
    LiveFlowTracker,
    classify_flow_records,
)


class FlowEngineTests(unittest.TestCase):
    def test_port_service_mapping(self):
        self.assertEqual(PORT_SERVICE_MAP.get(80), "http")
        self.assertEqual(PORT_SERVICE_MAP.get(443), "http_443")
        self.assertEqual(PORT_SERVICE_MAP.get(22), "ssh")
        self.assertEqual(PORT_SERVICE_MAP.get(53), "domain_u")
        self.assertEqual(PORT_SERVICE_MAP.get(21), "ftp")

    def test_tcp_state_mapping(self):
        self.assertEqual(TCP_STATE_FLAG_MAP.get("ESTABLISHED"), "SF")
        self.assertEqual(TCP_STATE_FLAG_MAP.get("SYN_SENT"), "S0")
        self.assertEqual(TCP_STATE_FLAG_MAP.get("CLOSE"), "REJ")
        self.assertEqual(TCP_STATE_FLAG_MAP.get("TIME_WAIT"), "S1")

    def test_flow_session_creation(self):
        session = FlowSession(
            flow_id="tcp:192.168.1.10:50000->10.0.0.1:80",
            src_ip="192.168.1.10",
            src_port=50000,
            dst_ip="10.0.0.1",
            dst_port=80,
            protocol_type="tcp",
            start_time=100.0,
            last_seen=105.0,
            state="ESTABLISHED",
        )
        self.assertEqual(session.protocol_type, "tcp")
        self.assertEqual(session.dst_port, 80)
        self.assertEqual(session.last_seen - session.start_time, 5.0)

    def test_live_flow_tracker_mock_connections(self):
        tracker = LiveFlowTracker(window_seconds=2.0)

        # Mock psutil.net_connections
        mock_conn1 = MagicMock()
        mock_conn1.type = 1  # SOCK_STREAM
        mock_conn1.laddr = ("192.168.1.5", 45000)
        mock_conn1.raddr = ("93.184.216.34", 80)
        mock_conn1.status = "ESTABLISHED"

        mock_conn2 = MagicMock()
        mock_conn2.type = 1
        mock_conn2.laddr = ("192.168.1.5", 45002)
        mock_conn2.raddr = ("93.184.216.34", 80)
        mock_conn2.status = "ESTABLISHED"

        mock_loopback = MagicMock()
        mock_loopback.type = 1
        mock_loopback.laddr = ("127.0.0.1", 5000)
        mock_loopback.raddr = ("127.0.0.1", 52000)
        mock_loopback.status = "ESTABLISHED"

        with patch("psutil.net_connections", return_value=[mock_conn1, mock_conn2, mock_loopback]):
            flows = tracker.update_from_os_connections()

        # Loopback should be skipped, 2 valid remote flows extracted
        self.assertEqual(len(flows), 2)
        flow0 = flows[0]
        self.assertEqual(flow0["dst_ip"], "93.184.216.34")
        self.assertEqual(flow0["service"], "http")
        self.assertEqual(flow0["flag"], "SF")
        self.assertEqual(flow0["protocol_type"], "tcp")
        self.assertIn("same_srv_rate", flow0)
        self.assertIn("count", flow0)

    def test_classify_flow_records_with_mock_pipeline(self):
        flows = [
            {
                "flow_id": "flow-1",
                "src_ip": "1.2.3.4",
                "dst_ip": "5.6.7.8",
                "dst_port": 80,
                "protocol_type": "tcp",
                "service": "http",
                "feat_a": 10.0,
                "feat_b": 20.0,
            }
        ]

        dummy_clf = DummyClassifier(strategy="constant", constant="Normal")
        dummy_clf.fit([[0, 0]], ["Normal"])

        scored = classify_flow_records(flows, dummy_clf, expected_columns=["feat_a", "feat_b"])
        self.assertEqual(len(scored), 1)
        self.assertEqual(scored[0]["prediction"], "Normal")
        self.assertEqual(scored[0]["risk"], "LOW")
        self.assertEqual(scored[0]["action_policy"], "ALERT_ONLY_NO_AUTO_BLOCK")

    def test_feature_provenance_schema(self):
        from scripts.flow_engine import FEATURE_PROVENANCE_SCHEMA, get_feature_provenance_summary
        self.assertIn("src_ip", FEATURE_PROVENANCE_SCHEMA)
        self.assertEqual(FEATURE_PROVENANCE_SCHEMA["src_ip"], "measured")
        self.assertEqual(FEATURE_PROVENANCE_SCHEMA["src_bytes"], "unavailable_without_packet_capture")
        self.assertEqual(FEATURE_PROVENANCE_SCHEMA["count"], "derived_sliding_window_ip_aggregation")
        
        summary = get_feature_provenance_summary()
        self.assertGreater(summary["measured_count"], 0)
        self.assertGreater(summary["derived_count"], 0)
        self.assertGreater(summary["unavailable_count"], 0)
        self.assertIn("Npcap/WinPcap", summary["telemetry_disclosure"])


if __name__ == "__main__":
    unittest.main()


