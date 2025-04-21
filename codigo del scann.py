#!/usr/bin/env python3
"""
Network Scanner - Interfaz interactiva con detección de OS
"""

import ipaddress
import socket
import subprocess
import os
import concurrent.futures
from datetime import datetime
import json
import platform
from enum import Enum
import re
from scapy.all import sr1, IP, TCP
import warnings
warnings.filterwarnings("ignore", category=RuntimeWarning)

class ScanType(Enum):
    TCP_CONNECT = 1
    SYN = 2

class InteractiveNetworkScanner:
    def __init__(self):
        self.results = {
            'network': '',
            'hosts': [],
            'scan_time': None,
            'total_hosts': 0,
            'active_hosts': 0,
            'services': {},
            'host_os': {}
        }
        self.scan_type = ScanType.TCP_CONNECT
        self.default_ports = "21-23,80,443,3389"
        self.os_fingerprints = {
            'Linux': {
                'ttl': 64,
                'window': 5840,
                'flags': 'S'
            },
            'Windows': {
                'ttl': 128,
                'window': 8192,
                'flags': 'S'
            },
            'Cisco': {
                'ttl': 255,
                'window': 4128,
                'flags': 'S'
            },
            'FreeBSD': {
                'ttl': 64,
                'window': 65535,
                'flags': 'S'
            }
        }

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        self.clear_screen()
        print("""
███████╗ ██████╗ █████╗ ███╗   ██╗███████╗██████╗ 
██╔════╝██╔════╝██╔══██╗████╗  ██║██╔════╝██╔══██╗
███████╗██║     ███████║██╔██╗ ██║█████╗  ██████╔╝
╚════██║██║     ██╔══██║██║╚██╗██║██╔══╝  ██╔══██╗
███████║╚██████╗██║  ██║██║ ╚████║███████╗██║  ██║
╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                  
        Escáner de Red Interactivo v2.1
""")

    def show_menu(self):
        while True:
            self.show_banner()
            print("\nMENU PRINCIPAL:")
            print("1. Escanear red completa (descubrir hosts)")
            print("2. Escanear puertos en un host específico")
            print("3. Escaneo rápido (puertos comunes)")
            print("4. Ver resultados del último escaneo")
            print("5. Guardar resultados")
            print("6. Configuración")
            print("0. Salir")

            choice = input("\nSeleccione una opción: ")

            if choice == '1':
                self.menu_scan_network()
            elif choice == '2':
                self.menu_scan_ports()
            elif choice == '3':
                self.menu_quick_scan()
            elif choice == '4':
                self.menu_show_results()
            elif choice == '5':
                self.menu_save_results()
            elif choice == '6':
                self.menu_config()
            elif choice == '0':
                print("\n¡Hasta pronto!")
                break
            else:
                input("\nOpción no válida. Presione Enter para continuar...")

    def menu_scan_network(self):
        self.show_banner()
        print("ESCANEO DE RED COMPLETA\n")
        print("Ejemplos de formato válido:")
        print("- 192.168.1.0/24 (toda la subred)")
        print("- 192.168.1.1-100 (rango específico)")
        print("- 192.168.1.5 (host individual)\n")

        network = input("Introduzca la red a escanear: ").strip()
        
        if not network:
            input("\nNo se ingresó ninguna red. Presione Enter para continuar...")
            return

        try:
            self.ping_sweep(network)
            input("\nEscaneo completado. Presione Enter para continuar...")
        except Exception as e:
            input(f"\nError: {e}. Presione Enter para continuar...")

    def menu_scan_ports(self):
        self.show_banner()
        print("ESCANEO DE PUERTOS EN HOST ESPECÍFICO\n")
        
        if not self.results['hosts']:
            host = input("Introduzca la dirección IP del host: ").strip()
        else:
            print("Hosts descubiertos recientemente:")
            for i, h in enumerate(self.results['hosts'], 1):
                print(f"{i}. {h}")
            print(f"{len(self.results['hosts'])+1}. Ingresar manualmente")
            
            choice = input("\nSeleccione un host o ingrese una IP: ").strip()
            
            if choice.isdigit() and 1 <= int(choice) <= len(self.results['hosts']):
                host = self.results['hosts'][int(choice)-1]
            else:
                host = choice

        if not host:
            input("\nNo se especificó ningún host. Presione Enter para continuar...")
            return

        print("\nPuertos a escanear (ejemplos):")
        print("- 80 (puerto individual)")
        print("- 1-100 (rango de puertos)")
        print("- 21,22,80,443 (lista de puertos)")
        print(f"- Dejar en blanco para usar puertos por defecto ({self.default_ports})\n")
        
        ports_input = input("Introduzca los puertos a escanear: ").strip()
        ports = ports_input if ports_input else self.default_ports

        try:
            ports_list = self.parse_ports(ports)
            print(f"\nIniciando escaneo en {host} ({len(ports_list)} puertos)...")
            self.port_scan(host, ports_list)
            input("\nEscaneo completado. Presione Enter para continuar...")
        except Exception as e:
            input(f"\nError: {e}. Presione Enter para continuar...")

    def menu_quick_scan(self):
        self.show_banner()
        print("ESCANEO RÁPIDO (PUERTOS COMUNES)\n")
        
        if not self.results['hosts']:
            host = input("Introduzca la dirección IP del host: ").strip()
            if not host:
                input("\nNo se especificó ningún host. Presione Enter para continuar...")
                return
        else:
            print("Hosts descubiertos recientemente:")
            for i, h in enumerate(self.results['hosts'], 1):
                print(f"{i}. {h}")
            
            choice = input("\nSeleccione un host o ingrese una IP: ").strip()
            
            if choice.isdigit() and 1 <= int(choice) <= len(self.results['hosts']):
                host = self.results['hosts'][int(choice)-1]
            else:
                host = choice

        print(f"\nIniciando escaneo rápido en {host} (puertos: {self.default_ports})...")
        try:
            ports_list = self.parse_ports(self.default_ports)
            self.port_scan(host, ports_list)
            input("\nEscaneo completado. Presione Enter para continuar...")
        except Exception as e:
            input(f"\nError: {e}. Presione Enter para continuar...")

    def menu_show_results(self):
        self.show_banner()
        print("RESULTADOS DEL ÚLTIMO ESCANEO\n")
        
        if not self.results['scan_time']:
            print("No hay resultados de escaneo disponibles.")
            input("\nPresione Enter para continuar...")
            return
        
        print(f"Red escaneada: {self.results['network']}")
        print(f"Fecha y hora: {self.results['scan_time']}")
        print(f"Hosts totales: {self.results['total_hosts']}")
        print(f"Hosts activos encontrados: {self.results['active_hosts']}\n")
        
        if self.results['hosts']:
            print("HOSTS ACTIVOS:")
            for host in self.results['hosts']:
                os_info = self.results['host_os'].get(host, 'No detectado')
                print(f"- {host} (Sistema operativo: {os_info})")
        
        if self.results['services']:
            print("\nSERVICIOS DETECTADOS:")
            for host, ports in self.results['services'].items():
                os_info = self.results['host_os'].get(host, 'No detectado')
                print(f"\nHost: {host} (OS: {os_info})")
                for port, data in ports.items():
                    print(f"  Puerto {port}: {data['service']}")
                    if data['banner']:
                        print(f"    Banner: {data['banner']}")
        
        input("\nPresione Enter para continuar...")

    def menu_save_results(self):
        self.show_banner()
        print("GUARDAR RESULTADOS\n")
        
        if not self.results['scan_time']:
            print("No hay resultados para guardar.")
            input("\nPresione Enter para continuar...")
            return
        
        filename = input("Nombre del archivo (sin extensión): ").strip()
        if not filename:
            print("No se especificó nombre de archivo.")
            input("\nPresione Enter para continuar...")
            return
        
        print("\nFormatos disponibles:")
        print("1. Texto (.txt)")
        print("2. JSON (.json)")
        choice = input("\nSeleccione formato: ").strip()
        
        if choice == '1':
            format = 'txt'
        elif choice == '2':
            format = 'json'
        else:
            print("Opción no válida.")
            input("\nPresione Enter para continuar...")
            return
        
        try:
            self.save_results(filename, format)
            input(f"\nResultados guardados en {filename}.{format}. Presione Enter para continuar...")
        except Exception as e:
            input(f"\nError al guardar: {e}. Presione Enter para continuar...")

    def menu_config(self):
        while True:
            self.show_banner()
            print("CONFIGURACIÓN\n")
            
            print(f"1. Puertos por defecto: {self.default_ports}")
            print(f"2. Tipo de escaneo: {self.scan_type.name}")
            print("0. Volver al menú principal")
            
            choice = input("\nSeleccione opción a modificar: ").strip()
            
            if choice == '1':
                new_ports = input(f"\nNuevos puertos por defecto (actual: {self.default_ports}): ").strip()
                if new_ports:
                    try:
                        self.parse_ports(new_ports)
                        self.default_ports = new_ports
                        input("\nConfiguración actualizada. Presione Enter para continuar...")
                    except Exception as e:
                        input(f"\nError: {e}. Presione Enter para continuar...")
            elif choice == '2':
                print("\nTipos de escaneo disponibles:")
                print("1. TCP Connect (no requiere privilegios)")
                print("2. SYN Scan (requiere root/admin)")
                
                scan_choice = input("\nSeleccione tipo de escaneo: ").strip()
                if scan_choice == '1':
                    self.scan_type = ScanType.TCP_CONNECT
                    input("\nConfiguración actualizada. Presione Enter para continuar...")
                elif scan_choice == '2':
                    self.scan_type = ScanType.SYN
                    input("\nConfiguración actualizada. Presione Enter para continuar...")
                else:
                    input("\nOpción no válida. Presione Enter para continuar...")
            elif choice == '0':
                break
            else:
                input("\nOpción no válida. Presione Enter para continuar...")

    def ping(self, host, timeout=1):
        """Realiza un ping a un host"""
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '1', '-w', str(timeout * 1000), str(host)]
            return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
        except:
            return False

    def detect_os(self, host):
        """Detecta el sistema operativo remoto usando técnicas de fingerprinting"""
        try:
            # Técnica 1: TTL y Window Size
            response = sr1(IP(dst=host)/TCP(dport=80,flags="S"), timeout=2, verbose=0)
            
            if not response:
                return "Desconocido (No response)"
            
            ttl = response[IP].ttl
            window_size = response[TCP].window
            
            for os_name, values in self.os_fingerprints.items():
                if (abs(ttl - values['ttl']) <= 5) and (window_size == values['window']):
                    return os_name
            
            # Técnica 2: Análisis de banners
            for port in [22, 445, 3389]:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(1)
                        s.connect((host, port))
                        banner = s.recv(1024).decode(errors='ignore').strip()
                        if 'Linux' in banner or 'SSH' in banner:
                            return 'Linux/Unix'
                        elif 'Windows' in banner or 'SMB' in banner:
                            return 'Windows'
                        elif 'Cisco' in banner:
                            return 'Cisco'
                except:
                    continue
            
            # Técnica 3: Clasificación por TTL
            if ttl <= 64:
                return f"Linux/Unix (TTL:{ttl})"
            elif ttl <= 128:
                return f"Windows (TTL:{ttl})"
            elif ttl <= 255:
                return f"Dispositivo de red (TTL:{ttl})"
            else:
                return f"Desconocido (TTL:{ttl})"
                
        except Exception as e:
            return f"Error en detección: {str(e)}"

    def ping_sweep(self, network, timeout=1, max_threads=50):
        """Escanea una red completa"""
        try:
            if '-' in network:
                base_ip, range_part = network.split('-')
                base_parts = base_ip.split('.')[:3]
                start = int(network.split('.')[-1].split('-')[0])
                end = int(range_part)
                
                self.results['network'] = f"{'.'.join(base_parts)}.{start}-{end}"
                self.results['total_hosts'] = end - start + 1
                hosts = [f"{'.'.join(base_parts)}.{i}" for i in range(start, end+1)]
            else:
                network_obj = ipaddress.ip_network(network, strict=False)
                self.results['network'] = str(network_obj)
                self.results['total_hosts'] = len(list(network_obj.hosts()))
                hosts = [str(host) for host in network_obj.hosts()]
            
            print(f"\nEscaneando {self.results['network']}...")
            
            active_hosts = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
                futures = {executor.submit(self.ping, host, timeout): host for host in hosts}
                
                for future in concurrent.futures.as_completed(futures):
                    host = futures[future]
                    if future.result():
                        active_hosts.append(host)
                        print(f"Host activo encontrado: {host}".ljust(50), end='\r')
            
            self.results['hosts'] = active_hosts
            self.results['active_hosts'] = len(active_hosts)
            self.results['scan_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            return active_hosts
            
        except Exception as e:
            raise Exception(f"Error en el escaneo de red: {e}")

    def parse_ports(self, ports_str):
        """Convierte cadena de puertos a lista ordenada"""
        ports = set()
        for part in ports_str.split(','):
            part = part.strip()
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end+1))
            else:
                ports.add(int(part))
        return sorted(ports)

    def tcp_connect_scan(self, host, port, timeout=1):
        """Escaneo TCP Connect normal"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                
                banner = None
                try:
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    pass
                
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                
                return True, {'service': service, 'banner': banner}
        except:
            return False, None

    def port_scan(self, host, ports, timeout=1, max_threads=100):
        """Escanea múltiples puertos en un host"""
        open_ports = {}
        
        # Detectar OS al inicio del escaneo
        os_info = self.detect_os(host)
        print(f"\n🔍 Detectando sistema operativo para {host}...")
        print(f"⚙️ Sistema operativo probable: {os_info}")
        self.results['host_os'][host] = os_info
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.tcp_connect_scan, host, port, timeout): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port = futures[future]
                is_open, data = future.result()
                if is_open:
                    open_ports[port] = data
                    print(f"Puerto {port}/tcp abierto - {data['service']}".ljust(50), end='\r')
                    if data['banner']:
                        print(f"  Banner: {data['banner']}")
        
        self.results['services'][host] = open_ports
        return open_ports

    def save_results(self, filename, format='txt'):
        """Guarda los resultados en un archivo"""
        try:
            if format == 'json':
                with open(f"{filename}.json", 'w') as f:
                    json.dump(self.results, f, indent=4)
            else:
                with open(f"{filename}.txt", 'w') as f:
                    f.write("=== RESULTADOS DE ESCANEO DE RED ===\n\n")
                    f.write(f"Red escaneada: {self.results['network']}\n")
                    f.write(f"Fecha y hora: {self.results['scan_time']}\n")
                    f.write(f"Hosts totales: {self.results['total_hosts']}\n")
                    f.write(f"Hosts activos: {self.results['active_hosts']}\n\n")
                    
                    if self.results['hosts']:
                        f.write("HOSTS ACTIVOS:\n")
                        for host in self.results['hosts']:
                            os_info = self.results['host_os'].get(host, 'No detectado')
                            f.write(f"- {host} (OS: {os_info})\n")
                    
                    if self.results['services']:
                        f.write("\nSERVICIOS DETECTADOS:\n")
                        for host, ports in self.results['services'].items():
                            os_info = self.results['host_os'].get(host, 'No detectado')
                            f.write(f"\nHost: {host} (OS: {os_info})\n")
                            for port, data in ports.items():
                                f.write(f"  Puerto {port}: {data['service']}\n")
                                if data['banner']:
                                    f.write(f"    Banner: {data['banner']}\n")
            
            return True
        except Exception as e:
            raise Exception(f"No se pudo guardar el archivo: {e}")

if __name__ == "__main__":
    try:
        scanner = InteractiveNetworkScanner()
        scanner.show_menu()
    except KeyboardInterrupt:
        print("\nPrograma terminado por el usuario.")
    except Exception as e:
        print(f"\nError inesperado: {e}")