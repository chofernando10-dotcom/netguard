import unittest
from src.parser import parse_config
from src.analyzer import load_policy, analyze_config
from src.acl_simulator import simulate_packet


class TestNetGuard(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy("policies/baseline-security.json")
        self.router_cfg = parse_config("sample_configs/router_branch_01.txt")
        self.switch_cfg = parse_config("sample_configs/switch_access_02.txt")

    def test_router_audit_findings(self) -> None:
        findings = analyze_config(self.router_cfg, self.policy)
        rule_ids = {f["rule_id"] for f in findings}
        self.assertEqual(rule_ids, {"NET-001", "NET-002", "NET-003", "NET-004"})

    def test_switch_audit_vlan1_and_telnet(self) -> None:
        findings = analyze_config(self.switch_cfg, self.policy)
        rule_ids = {f["rule_id"] for f in findings}
        self.assertIn("NET-001", rule_ids)
        self.assertIn("NET-003", rule_ids)
        self.assertIn("NET-005", rule_ids)

    def test_acl_simulator_explicit_permit(self) -> None:
        acl_entries = self.router_cfg["acls"]["WAN_IN"]
        result = simulate_packet(acl_entries, "8.8.8.8", "203.0.113.2", "tcp", 443)
        self.assertEqual(result["decision"], "PERMIT")
        self.assertEqual(result["step"], 1)

    def test_acl_simulator_implicit_deny(self) -> None:
        custom_acl = [
            "permit tcp any host 203.0.113.2 eq 443",
            "permit icmp any any",
        ]
        result = simulate_packet(custom_acl, "192.168.1.50", "203.0.113.2", "tcp", 22)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["matched_rule"], "implicit deny ip any any")


if __name__ == "__main__":
    unittest.main()