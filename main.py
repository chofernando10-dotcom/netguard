import argparse
import sys
from src.parser import parse_config
from src.analyzer import load_policy, analyze_config
from src.acl_simulator import simulate_packet
from src.remediator import generate_remediation_script
from src.reporter import generate_markdown_report


def cmd_audit(args: argparse.Namespace) -> None:
    parsed = parse_config(args.config)
    policy = load_policy(args.policy)
    findings = analyze_config(parsed, policy)
    remediation = generate_remediation_script(parsed["hostname"], findings)

    print(f"\n=== Auditoría de Seguridad: {parsed['hostname']} ===")
    print(f"Archivo: {args.config}")
    print(f"Hallazgos encontrados: {len(findings)}\n")

    for f in findings:
        print(f"[{f['severity']}] {f['rule_id']} - {f['name']}")
        print(f"   Evidencia: {f['evidence']}\n")

    if args.report:
        generate_markdown_report(parsed, findings, remediation, output_path=args.report)
        print(f"Reporte guardado en: {args.report}")


def cmd_simulate(args: argparse.Namespace) -> None:
    parsed = parse_config(args.config)
    acls = parsed.get("acls", {})

    if args.acl not in acls:
        print(f"Error: La ACL '{args.acl}' no existe en {args.config}. ACLs disponibles: {list(acls.keys())}")
        sys.exit(1)

    result = simulate_packet(
        acl_entries=acls[args.acl],
        src_ip=args.src,
        dst_ip=args.dst,
        protocol=args.protocol,
        dst_port=args.port,
    )

    print(f"\n=== Simulación de Paquete en ACL '{args.acl}' ({parsed['hostname']}) ===")
    print(f"Tráfico: {args.protocol.upper()} {args.src} -> {args.dst}:{args.port or 'any'}")
    print(f"Decisión final: {result['decision']} (Regla: {result['matched_rule']})\n")
    print("Traza de evaluación:")
    for step in result["trace"]:
        print(f"  - {step}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard - Auditor de Seguridad y Simulador de ACLs para Configuraciones de Red",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcomando: audit
    audit_parser = subparsers.add_parser("audit", help="Audita un archivo de configuración contra una política")
    audit_parser.add_argument("config", help="Ruta al archivo de configuración de red")
    audit_parser.add_argument(
        "--policy",
        default="policies/baseline-security.json",
        help="Ruta al archivo JSON de políticas (por defecto: policies/baseline-security.json)",
    )
    audit_parser.add_argument("--report", help="Ruta de salida para guardar el reporte en Markdown (ej. reporte.md)")
    audit_parser.set_defaults(func=cmd_audit)

    # Subcomando: simulate
    sim_parser = subparsers.add_parser("simulate", help="Simula un paquete contra una ACL específica")
    sim_parser.add_argument("config", help="Ruta al archivo de configuración de red")
    sim_parser.add_argument("--acl", required=True, help="Nombre de la ACL extendida a evaluar")
    sim_parser.add_argument("--src", required=True, help="Dirección IP origen (ej. 10.0.0.5)")
    sim_parser.add_argument("--dst", required=True, help="Dirección IP destino (ej. 203.0.113.2)")
    sim_parser.add_argument("--protocol", default="tcp", help="Protocolo (tcp, udp, icmp, ip)")
    sim_parser.add_argument("--port", type=int, default=None, help="Puerto destino (ej. 443, 22, 80)")
    sim_parser.set_defaults(func=cmd_simulate)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()