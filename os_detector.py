from scapy.all import IP, ICMP, sr1
import sys
import argparse
import ipaddress
from colorama import Fore, Style

# Diccionario mejorado de TTLs y sistemas operativos
TTL_OS_MAPPING = {
    (30, 32): ["Windows 95/98/NT3.51"],
    (59, 60): ["HPJetDirect", "AIX"],
    (63, 64): ["Linux", "FreeBSD", "Red Hat 9"],
    (127, 128): ["Windows (XP/7/8/10/11)"],
    (254, 255): ["Solaris", "Cisco", "Unix"],
    (64, 65): ["MacOS", "iOS"],
    (128, 129): ["Windows Server"],
    (255, 256): ["NetBSD", "OpenBSD"]
}

def get_os_from_ttl(ttl):
    """Determina el sistema operativo en base al TTL."""
    for ttl_range, os_list in TTL_OS_MAPPING.items():
        if ttl_range[0] <= ttl <= ttl_range[1]:
            return os_list
    return ["Desconocido"]

def normalize_ttl(ttl):
    """Normaliza el TTL teniendo en cuenta los valores más comunes."""
    if ttl > 200:
        return 255
    elif ttl > 100:
        return 128
    else:
        return 64

def send_icmp_request(dst_addr, verbose=False):
    """Envía una solicitud ICMP y devuelve la respuesta."""
    try:
        packet = IP(dst=dst_addr) / ICMP()
        reply = sr1(packet, timeout=2, verbose=0)
        return reply
    except PermissionError:
        print(Fore.RED + "[ERROR] Se requieren permisos de administrador/root para ejecutar este script." + Style.RESET_ALL)
        sys.exit(1)
    except Exception as e:
        if verbose:
            print(Fore.RED + f"[ERROR] {str(e)}" + Style.RESET_ALL)
        return None

def validate_ip(ip):
    """Valida si la IP es correcta y no es IPv6."""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 6:
            print(Fore.RED + "[ERROR] Este script no soporta direcciones IPv6." + Style.RESET_ALL)
            return False
        return True
    except ValueError:
        return False

def main():
    parser = argparse.ArgumentParser(description="Detector de SO basado en TTL.")
    parser.add_argument("ip", help="Dirección IP del host a escanear.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detallado.")
    args = parser.parse_args()

    dst_addr = args.ip
    verbose = args.verbose

    if not validate_ip(dst_addr):
        print(Fore.RED + "[ERROR] Dirección IP inválida." + Style.RESET_ALL)
        sys.exit(1)

    print(Fore.YELLOW + f"[INFO] Enviando solicitud ICMP a {dst_addr}..." + Style.RESET_ALL)
    reply = send_icmp_request(dst_addr, verbose)

    if reply:
        ttl = reply.ttl
        print(Fore.GREEN + f"[INFO] TTL recibido: {ttl}" + Style.RESET_ALL)

        normalized_ttl = normalize_ttl(ttl)
        if verbose:
            print(Fore.CYAN + f"[DEBUG] TTL normalizado: {normalized_ttl}" + Style.RESET_ALL)

        os_list = get_os_from_ttl(normalized_ttl)
        print(Fore.BLUE + "[INFO] Sistemas operativos posibles:" + Style.RESET_ALL)
        for os_name in os_list:
            print(Fore.MAGENTA + f" - {os_name}" + Style.RESET_ALL)
    else:
        print(Fore.RED + "[ERROR] No se recibió respuesta del host." + Style.RESET_ALL)

if __name__ == "__main__":
    main()
