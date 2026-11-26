from datetime import datetime
from pathlib import Path
from typing import Any


def generate_markdown_report(
    parsed_config: dict[str, Any],
    findings: list[dict[str, Any]],
    remediation_script: str,
    output_path: str | None = None,
) -> str:
    """Construye un reporte de auditoría en formato Markdown."""
    hostname = parsed_config.get("hostname", "UNKNOWN")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_lines = [
        f"# Reporte de Auditoría de Red - `{hostname}`",
        f"- **Archivo analizado:** `{parsed_config.get('file')}`",
        f"- **Fecha de ejecución:** {timestamp}",
        f"- **Total de hallazgos:** {len(findings)}",
        "",
        "## Hallazgos Detectados",
    ]

    if not findings:
        report_lines.append("No se encontraron vulnerabilidades según la política aplicada.")
    else:
        report_lines.append("| ID | Severidad | Regla | Evidencia |")
        report_lines.append("|---|---|---|---|")
        for f in findings:
            report_lines.append(
                f"| `{f['rule_id']}` | **{f['severity']}** | {f['name']} | `{f['evidence']}` |"
            )

    report_lines.extend([
        "",
        "## Script de Remediación Sugerido",
        "```ios",
        remediation_script,
        "```",
    ])

    report_content = "\n".join(report_lines)

    if output_path:
        Path(output_path).write_text(report_content, encoding="utf-8")

    return report_content