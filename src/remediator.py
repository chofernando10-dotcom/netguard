from typing import Any


def generate_remediation_script(hostname: str, findings: list[dict[str, Any]]) -> str:
    """Genera un bloque de comandos de remediación listo para aplicar en consola."""
    if not findings:
        return f"! El dispositivo {hostname} cumple con todas las políticas evaluadas."

    lines = [
        f"! =====================================================",
        f"! Script de Remediacion Automatizada - {hostname}",
        f"! =====================================================",
        "configure terminal",
    ]

    seen_commands: set[str] = set()
    for finding in findings:
        cmd_block = finding["remediation"]
        if cmd_block not in seen_commands:
            lines.append(f"! Correccion para [{finding['rule_id']}] {finding['name']}")
            lines.append(cmd_block)
            seen_commands.add(cmd_block)

    lines.append("end")
    lines.append("write memory")
    return "\n".join(lines)