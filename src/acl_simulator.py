import ipaddress
from typing import Any


def _ip_matches(target_ip: str, rule_spec: str) -> bool:
    """Evalúa si una IP coincide con 'any', 'host X.X.X.X' o 'IP WILDCARD'."""
    if rule_spec == "any":
        return True

    ip_obj = ipaddress.ip_address(target_ip)

    if rule_spec.startswith("host "):
        host_ip = ipaddress.ip_address(rule_spec.split("host ", 1)[1])
        return ip_obj == host_ip

    parts = rule_spec.split()
    if len(parts) == 2:
        net_ip, wildcard = parts
        # Convertir wildcard mask a subnet mask
        net_octets = [int(x) for x in net_ip.split(".")]
        wc_octets = [int(x) for x in wildcard.split(".")]
        mask_octets = [255 - w for w in wc_octets]
        network_str = f"{'.'.join(map(str, net_octets))}/{'.'.join(map(str, mask_octets))}"
        network = ipaddress.ip_network(network_str, strict=False)
        return ip_obj in network

    return False


def _parse_acl_entry(entry: str) -> dict[str, Any]:
    """Descompone una línea de ACL extendida en acción, protocolo, origen, destino y puerto."""
    tokens = entry.split()
    action = tokens[0]      # permit | deny
    protocol = tokens[1]    # ip | tcp | udp | icmp

    idx = 2
    if tokens[idx] == "any":
        src = "any"
        idx += 1
    elif tokens[idx] == "host":
        src = f"host {tokens[idx + 1]}"
        idx += 2
    else:
        src = f"{tokens[idx]} {tokens[idx + 1]}"
        idx += 2

    if tokens[idx] == "any":
        dst = "any"
        idx += 1
    elif tokens[idx] == "host":
        dst = f"host {tokens[idx + 1]}"
        idx += 2
    else:
        dst = f"{tokens[idx]} {tokens[idx + 1]}"
        idx += 2

    port = None
    if idx < len(tokens) and tokens[idx] == "eq":
        port = int(tokens[idx + 1])

    return {
        "raw": entry,
        "action": action,
        "protocol": protocol,
        "src": src,
        "dst": dst,
        "port": port,
    }


def simulate_packet(
    acl_entries: list[str],
    src_ip: str,
    dst_ip: str,
    protocol: str = "tcp",
    dst_port: int | None = None,
) -> dict[str, Any]:
    """Simula el recorrido de un paquete a través de una ACL paso a paso."""
    trace: list[str] = []
    protocol = protocol.lower()

    for step, raw_entry in enumerate(acl_entries, start=1):
        rule = _parse_acl_entry(raw_entry)

        proto_match = rule["protocol"] == "ip" or rule["protocol"] == protocol
        src_match = _ip_matches(src_ip, rule["src"])
        dst_match = _ip_matches(dst_ip, rule["dst"])
        port_match = rule["port"] is None or (dst_port is not None and rule["port"] == dst_port)

        if proto_match and src_match and dst_match and port_match:
            trace.append(f"Paso {step}: COINCIDE con '{raw_entry}' -> {rule['action'].upper()}")
            return {
                "decision": rule["action"].upper(),
                "matched_rule": raw_entry,
                "step": step,
                "trace": trace,
            }
        else:
            trace.append(f"Paso {step}: No coincide con '{raw_entry}'")

    # Regla implícita al final de toda ACL
    trace.append("Final: No hubo coincidencia -> DENY (implicit deny any any)")
    return {
        "decision": "DENY",
        "matched_rule": "implicit deny ip any any",
        "step": len(acl_entries) + 1,
        "trace": trace,
    }