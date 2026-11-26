import json
from pathlib import Path
from typing import Any


def load_policy(policy_path: str = "policies/baseline-security.json") -> dict[str, Any]:
    """Carga las reglas de seguridad desde un archivo JSON."""
    path = Path(policy_path)
    if not path.exists():
        raise FileNotFoundError(f"No se encontró el archivo de políticas: {policy_path}")
    return json.loads(path.read_text(encoding="utf-8"))


def analyze_config(parsed_config: dict[str, Any], policy: dict[str, Any]) -> list[dict[str, Any]]:
    """Evalúa una configuración parseada contra las reglas definidas en la política."""
    rules_by_id = {rule["id"]: rule for rule in policy.get("rules", [])}
    findings: list[dict[str, Any]] = []

    def add_finding(rule_id: str, evidence: str) -> None:
        rule = rules_by_id.get(rule_id)
        if rule:
            findings.append({
                "rule_id": rule["id"],
                "name": rule["name"],
                "severity": rule["severity"],
                "description": rule["description"],
                "evidence": evidence,
                "remediation": rule["remediation"],
            })

    # NET-001: Telnet habilitado en VTY
    if "telnet" in parsed_config.get("vty_transports", []):
        add_finding(
            "NET-001",
            f"line vty transport input: {', '.join(parsed_config['vty_transports'])}",
        )

    # NET-002: HTTP sin cifrar habilitado
    if parsed_config.get("http_server"):
        add_finding("NET-002", "ip http server habilitado")

    # NET-003: Contraseñas sin cifrado
    if not parsed_config.get("password_encryption"):
        add_finding("NET-003", "no service password-encryption")

    # NET-004: ACL con 'permit ip any any'
    for acl_name, entries in parsed_config.get("acls", {}).items():
        for entry in entries:
            if entry.startswith("permit ip any any"):
                add_finding("NET-004", f"ACL '{acl_name}': {entry}")

    # NET-005: Puertos de acceso en VLAN 1
    for iface in parsed_config.get("interfaces", []):
        if iface.get("mode") == "access" and iface.get("access_vlan") == "1":
            add_finding("NET-005", f"Interfaz {iface['name']} asignada a VLAN 1")

    return findings