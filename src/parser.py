from pathlib import Path
from typing import Any


def parse_config(file_path: str) -> dict[str, Any]:
    """Lee un archivo de configuración de red y extrae sus secciones clave."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"No se encontró el archivo de configuración: {file_path}")

    lines = path.read_text(encoding="utf-8").splitlines()

    parsed: dict[str, Any] = {
        "file": str(path),
        "hostname": "UNKNOWN",
        "password_encryption": False,
        "http_server": False,
        "https_server": False,
        "vty_transports": [],
        "interfaces": [],
        "acls": {},
    }

    current_interface: dict[str, Any] | None = None
    current_acl: str | None = None
    in_vty_block = False

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("!"):
            continue

        # Hostname
        if line.startswith("hostname "):
            parsed["hostname"] = line.split("hostname ", 1)[1].strip()

        # Servicios globales
        elif line == "service password-encryption":
            parsed["password_encryption"] = True
        elif line == "no service password-encryption":
            parsed["password_encryption"] = False
        elif line == "ip http server":
            parsed["http_server"] = True
        elif line == "ip http secure-server":
            parsed["https_server"] = True

        # Bloques de interfaz
        elif line.startswith("interface "):
            in_vty_block = False
            current_acl = None
            current_interface = {
                "name": line.split("interface ", 1)[1].strip(),
                "mode": None,
                "access_vlan": None,
                "ip_address": None,
                "acl_in": None,
            }
            parsed["interfaces"].append(current_interface)

        # Bloques de ACL extendida
        elif line.startswith("ip access-list extended "):
            in_vty_block = False
            current_interface = None
            current_acl = line.split("ip access-list extended ", 1)[1].strip()
            parsed["acls"][current_acl] = []

        # Líneas VTY (acceso remoto)
        elif line.startswith("line vty "):
            in_vty_block = True
            current_interface = None
            current_acl = None

        elif line.startswith("line "):
            in_vty_block = False
            current_interface = None
            current_acl = None

        # Detalles dentro de bloques activos
        elif raw_line.startswith(" "):
            if current_interface is not None:
                if line.startswith("switchport mode "):
                    current_interface["mode"] = line.split("switchport mode ", 1)[1].strip()
                elif line.startswith("switchport access vlan "):
                    current_interface["access_vlan"] = line.split("switchport access vlan ", 1)[1].strip()
                elif line.startswith("ip address "):
                    current_interface["ip_address"] = line.split("ip address ", 1)[1].strip()
                elif line.startswith("ip access-group "):
                    parts = line.split()
                    if len(parts) >= 4 and parts[3] == "in":
                        current_interface["acl_in"] = parts[2]

            elif current_acl is not None:
                parsed["acls"][current_acl].append(line)

            elif in_vty_block and line.startswith("transport input "):
                protocols = line.split("transport input ", 1)[1].strip().split()
                parsed["vty_transports"].extend(protocols)

    return parsed