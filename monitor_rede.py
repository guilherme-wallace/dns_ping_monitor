import tkinter as tk
from tkinter import ttk
import threading
import time
from queue import Queue, Empty
import subprocess
import re
import requests
import netifaces
import dns.resolver
import sys
import json
import datetime

# --- Configuração de Logging ---
LOG_FILE = "network_monitor_log.txt"

def log_message(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)
    print(log_entry.strip()) # Also print to console for immediate feedback

# --- 1. Funções de Obtenção de Informações de Rede ---

# Normaliza um MAC Address (remove separadores e converte para maiúsculas)
def normalize_mac(mac_str):
    if mac_str:
        return mac_str.replace(':', '').replace('-', '').upper()
    return ""

# Função aprimorada para obter mapeamento de nomes de interface
# Agora usa MAC Address para correlacionar, e inclui Status/LinkSpeed
def get_interface_friendly_names_windows_v6():
    # This map will store: {normalized_mac_address: {'description': '...', 'status': '...', 'speed': '...'}}
    mac_to_details_map = {}

    if sys.platform == "win32":
        try:
            # Include Status and LinkSpeed in the PowerShell command
            command = [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-NetAdapter -Name * | Select-Object Name, InterfaceDescription, MacAddress, Status, LinkSpeed, Guid | ConvertTo-Json"
            ]
            result = subprocess.run(
                command,
                capture_output=True, text=True, encoding='utf-8', errors='replace',
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=10
            )
            output = result.stdout
            
            log_message(f"PowerShell Get-NetAdapter (v6) Raw Output:\n{output}")
            
            data = json.loads(output)
            
            if not isinstance(data, list):
                data = [data]

            for adapter in data:
                mac_address_ps = adapter.get("MacAddress")
                description = adapter.get("InterfaceDescription")
                status = adapter.get("Status")
                link_speed = adapter.get("LinkSpeed")
                
                if mac_address_ps and description:
                    normalized_mac_ps = normalize_mac(mac_address_ps)
                    mac_to_details_map[normalized_mac_ps] = {
                        "description": description,
                        "status": status,
                        "speed": link_speed
                    }

        except json.JSONDecodeError as e:
            log_message(f"Erro ao decodificar JSON do PowerShell v6: {e}. Output: {output[:500]}...")
        except Exception as e:
            log_message(f"Erro ao obter nomes amigáveis das interfaces (PowerShell v6): {e}")
    
    return mac_to_details_map

def get_system_dns_servers_dnspython():
    dns_servers = []
    try:
        resolver = dns.resolver.Resolver()
        for ns in resolver.nameservers:
            if ns not in dns_servers:
                dns_servers.append(ns)
    except Exception as e:
        log_message(f"Erro ao obter DNSs com dnspython: {e}")
        pass 
    return dns_servers

def get_network_details():
    formatted_info = {}
    
    system_dns_servers = get_system_dns_servers_dnspython()
    system_dns_str = ", ".join(system_dns_servers) if system_dns_servers else "N/A"
    
    # Get interface friendly names and other details (MAC-based)
    mac_to_details_map = get_interface_friendly_names_windows_v6()
    log_message(f"Mapeamento MAC para detalhes do adaptador: {mac_to_details_map}")

    all_gateways = {}
    try:
        gws = netifaces.gateways()
        log_message(f"Gateways brutos do netifaces: {gws}")
        for gw_family in [netifaces.AF_INET, netifaces.AF_INET6]:
            if gw_family in gws:
                for gw_info_tuple in gws[gw_family]:
                    if len(gw_info_tuple) >= 2:
                        gw_ip = gw_info_tuple[0].split('%')[0]
                        iface = gw_info_tuple[1]
                        
                        if iface not in all_gateways:
                            all_gateways[iface] = []
                        if gw_ip not in all_gateways[iface]:
                            if not (gw_family == netifaces.AF_INET6 and gw_ip.startswith('fe80::')):
                                all_gateways[iface].append(gw_ip)
                            elif gw_family == netifaces.AF_INET6 and gw_ip.startswith('fe80::') and not [x for x in all_gateways[iface] if not x.startswith('fe80::')]:
                                all_gateways[iface].append(gw_ip) 
    except Exception as e:
        log_message(f"Erro ao obter gateways com netifaces: {e}")

    log_message(f"Interfaces brutas do netifaces: {netifaces.interfaces()}")
    for iface_name in netifaces.interfaces(): # iface_name here is the GUID like '{...}'
        log_message(f"Processando interface netifaces: {iface_name}")
        
        display_name = iface_name.replace('{', '').replace('}', '').strip() # Default to cleaned GUID

        # Attempt to get MAC address from netifaces
        netifaces_mac = None
        if netifaces.AF_LINK in netifaces.ifaddresses(iface_name):
            for link in netifaces.ifaddresses(iface_name)[netifaces.AF_LINK]:
                if 'addr' in link:
                    netifaces_mac = normalize_mac(link['addr'])
                    log_message(f"  MAC encontrado para {iface_name}: {netifaces_mac}")
                    break
        
        adapter_details = None
        # Try to find adapter details using MAC address map
        if netifaces_mac and netifaces_mac in mac_to_details_map:
            adapter_details = mac_to_details_map[netifaces_mac]
            display_name = adapter_details["description"] # Use friendly description
            log_message(f"  Nome amigável ENCONTRADO (via MAC) para {iface_name}: {display_name}")
        else:
            log_message(f"  Nome amigável NÃO encontrado (via MAC) para {iface_name}. Usando: {display_name} (limpo)")

        info = {
            "ipv4_addresses": [],
            "ipv6_addresses": [],
            "dns_servers": system_dns_servers, 
            "default_gateways": all_gateways.get(iface_name, [])
        }

        if netifaces.AF_INET in netifaces.ifaddresses(iface_name):
            for link in netifaces.ifaddresses(iface_name)[netifaces.AF_INET]:
                if 'addr' in link and link['addr'] != '127.0.0.1':
                    info["ipv4_addresses"].append(link['addr'])
                    log_message(f"  IPv4 encontrado para {iface_name}: {link['addr']}")

        if netifaces.AF_INET6 in netifaces.ifaddresses(iface_name):
            for link in netifaces.ifaddresses(iface_name)[netifaces.AF_INET6]:
                if 'addr' in link and not link['addr'].startswith('fe80::') and link['addr'] != '::1':
                    info["ipv6_addresses"].append(link['addr'].split('%')[0])
                    log_message(f"  IPv6 encontrado para {iface_name}: {link['addr'].split('%')[0]}")

        # Only add interface info if it has at least one IPv4 or IPv6 address or a gateway
        if info["ipv4_addresses"] or info["ipv6_addresses"] or info["default_gateways"]:
            formatted_info[display_name] = {
                "ipv4": ", ".join(info["ipv4_addresses"]) if info["ipv4_addresses"] else "N/A",
                "ipv6": ", ".join(info["ipv6_addresses"]) if info["ipv6_addresses"] else "N/A",
                "dns": ", ".join(info["dns_servers"]) if info["dns_servers"] else "N/A",
                "gateway": ", ".join(info["default_gateways"]) if info["default_gateways"] else "N/A",
                # Add Status and Speed
                "status": adapter_details["status"] if adapter_details else "N/A",
                "speed": adapter_details["speed"] if adapter_details else "N/A"
            }
            log_message(f"  Informações formatadas para '{display_name}': {formatted_info[display_name]}")
        else:
            log_message(f"  Interface '{iface_name}' não possui IPs ou Gateways relevantes. Ignorando.")

    public_ip = get_public_ip() 
    log_message(f"IP Público: {public_ip}")

    return {
        "adapters": formatted_info,
        "public_ipv4": public_ip,
        "system_dns_servers_str": system_dns_str
    }

def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=5)
        response.raise_for_status()
        data = response.json()
        return data["ip"]
    except requests.exceptions.RequestException as e:
        return f"Erro ao obter IP público: {e}"

# --- 2. Função de Ping ---
def ping_address(target_address):
    ping_result = {
        "rtt": "N/A",
        "resolved_ip": target_address, 
        "sent": 0,
        "received": 0,
        "lost": 0,
        "loss_percent": 0, 
        "status": "Falha" 
    }
    
    try:
        command = ["ping", "-n", "1", "-w", "1000", target_address]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=3, 
            encoding='utf-8',
            errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        output = result.stdout

        ip_match = re.search(r"Disparando .* \[([\d\.:a-fA-F]+)\]", output, re.IGNORECASE)
        if ip_match:
            ping_result["resolved_ip"] = ip_match.group(1)

        rtt_match = re.search(r"Tempo\s*=\s*(\d+)ms|tempo\s*=\s*(\d+)ms", output, re.IGNORECASE)
        if rtt_match:
            ping_result["rtt"] = f"{rtt_match.group(1) or rtt_match.group(2)}ms"
            ping_result["status"] = "Sucesso"
            ping_result["sent"] = 1
            ping_result["received"] = 1
            ping_result["lost"] = 0
            ping_result["loss_percent"] = 0
        else:
            ping_result["sent"] = 1 
            ping_result["received"] = 0
            ping_result["lost"] = 1
            ping_result["loss_percent"] = 100 

            if "Esgotado o tempo limite do pedido" in output or "Host de destino inacessível" in output:
                ping_result["rtt"] = "Tempo limite"
                ping_result["status"] = "Tempo limite"
            elif "não pôde encontrar o host" in output.lower() or "nome ou serviço não conhecido" in output.lower() or "solicitação de ping não pôde encontrar o host" in output.lower():
                ping_result["rtt"] = "Host não encontrado"
                ping_result["status"] = "Host não encontrado"
            else:
                ping_result["rtt"] = "Falha desconhecida"
                ping_result["status"] = "Falha desconhecida"
            
    except subprocess.TimeoutExpired:
        ping_result["rtt"] = "Tempo limite (Subprocess)"
        ping_result["status"] = "Tempo limite (Subprocess)"
        ping_result["sent"] = 1
        ping_result["received"] = 0
        ping_result["lost"] = 1
        ping_result["loss_percent"] = 100
    except Exception as e:
        ping_result["rtt"] = f"Erro: {e}"
        ping_result["status"] = f"Erro: {e}"
        ping_result["sent"] = 0 
        ping_result["received"] = 0
        ping_result["lost"] = 0
        ping_result["loss_percent"] = 0 

    return ping_result

# --- 3. Classe da Aplicação GUI ---
class DNSPingApp:
    def __init__(self, master):
        self.master = master
        master.title("Monitor de Latência de Rede")
        
        self.style = ttk.Style(master)
        self.style.theme_use('clam') 

        self.primary_color = "#4CAF50" # Modern Green
        self.secondary_color = "#66BB6A" # Lighter Green
        self.background_color = "#F5F5F5" # Light Grayish Background
        self.text_color = "#333333" # Dark Gray
        self.border_color = "#E0E0E0" # Lighter Border
        self.success_color = "#28a745" # Bootstrap green
        self.warning_color = "#ffc107" # Bootstrap yellow
        self.error_color = "#dc3545" # Bootstrap red
        self.info_color = "#17a2b8" # Bootstrap info blue

        self.style.configure("TLabel", background=self.background_color, foreground=self.text_color, font=('Segoe UI', 10))
        self.style.configure("TButton", background=self.primary_color, foreground="white", font=('Segoe UI', 10, 'bold'), padding=8)
        self.style.map("TButton",
                       background=[('active', self.secondary_color)],
                       foreground=[('active', 'white')])
        self.style.configure("TLabelframe", background=self.background_color, bordercolor=self.border_color, relief="solid", borderwidth=1)
        self.style.configure("TLabelframe.Label", background=self.background_color, foreground=self.primary_color, font=('Segoe UI', 10, 'bold'))
        self.style.configure("Card.TLabelframe", background="#FFFFFF", bordercolor=self.border_color, relief="raised", borderwidth=1)
        self.style.configure("Card.TLabelframe.Label", background="#FFFFFF", foreground=self.text_color, font=('Segoe UI', 10, 'bold'))
        self.style.configure("Status.TLabel", font=('Segoe UI', 10, 'bold')) # For colored status text

        master.configure(bg=self.background_color)
        master.geometry("700x750") # Adjust default size

        self.ping_interval_seconds = 2 

        self.running = False
        self.ping_thread = None
        self.result_queue = Queue()
        self.ping_history = [] # Stores full results for overall stats
        self.current_ping_stats = {} # Stores accumulated stats for live display on cards

        self.network_info_frames = {} 
        self.ping_result_labels = {} 
        self.overall_statistics_content = "Nenhum teste realizado." # Store content for modal

        self.setup_ui()
        self.load_network_info() 
        self.process_queue() 

    def setup_ui(self):
        # --- Frame Superior: Informações da Máquina e Rede ---
        self.top_info_main_frame = ttk.LabelFrame(self.master, text="Informações da Máquina e Rede", padding="15", style="TLabelframe")
        self.top_info_main_frame.pack(pady=15, padx=15, fill="x")

        ttk.Label(self.top_info_main_frame, text="Endereço IPv4 Público:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky="nw", pady=5, padx=10)
        self.public_ip_label = ttk.Label(self.top_info_main_frame, text="Carregando...", font=('Segoe UI', 10), wraplength=400, justify="left")
        self.public_ip_label.grid(row=0, column=1, sticky="nw", pady=5, padx=10)

        ttk.Label(self.top_info_main_frame, text="Servidores DNS do Sistema:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky="nw", pady=5, padx=10)
        self.system_dns_label = ttk.Label(self.top_info_main_frame, text="Carregando...", font=('Segoe UI', 10), wraplength=400, justify="left")
        self.system_dns_label.grid(row=1, column=1, sticky="nw", pady=5, padx=10)
        
        self.adapter_info_container = ttk.Frame(self.top_info_main_frame, style="TFrame")
        self.adapter_info_container.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)
        self.top_info_main_frame.grid_columnconfigure(1, weight=1)

        # --- Frame Central: Resultados de Ping ---
        ping_results_container_frame = ttk.Frame(self.master, style="TFrame")
        ping_results_container_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)

        results_canvas = tk.Canvas(ping_results_container_frame, borderwidth=0, highlightthickness=0, background=self.background_color)
        self.ping_cards_frame = ttk.Frame(results_canvas, padding="10 0 10 0", style="TFrame")
        results_canvas.pack(side="left", fill="both", expand=True)

        vsb = ttk.Scrollbar(ping_results_container_frame, orient="vertical", command=results_canvas.yview)
        vsb.pack(side="right", fill="y")
        results_canvas.configure(yscrollcommand=vsb.set)

        results_canvas.create_window((0, 0), window=self.ping_cards_frame, anchor="nw", tags="results_frame")
        self.ping_cards_frame.bind("<Configure>", lambda e: results_canvas.configure(scrollregion=results_canvas.bbox("all")))

        # Ping targets (Gateway is NOT included here)
        self.ping_targets = {
            "DNS Google (8.8.8.8)": "8.8.8.8",
            "DNS Cloudflare (1.1.1.1)": "1.1.1.1",
            "Conteúdo 01 (google.com)": "google.com",
            "Conteúdo 02 (youtube.com)": "youtube.com", 
            "Conteúdo 03 (facebook.com)": "facebook.com",
        }
        
        self.create_ping_cards(self.ping_cards_frame)

        for i in range(3):
            self.ping_cards_frame.grid_columnconfigure(i, weight=1)

        # --- Frame Inferior Direito: Botões e Botão de Estatísticas (NÃO MAIS TEXT) ---
        bottom_right_frame = ttk.Frame(self.master, padding="15", style="TFrame")
        bottom_right_frame.pack(side="right", fill="y", padx=15, pady=10)

        self.start_button = ttk.Button(bottom_right_frame, text="INICIAR TESTE", command=self.start_ping, style="TButton")
        self.start_button.pack(pady=10, fill="x")

        self.stop_button = ttk.Button(bottom_right_frame, text="PARAR TESTE", command=self.stop_ping, state=tk.DISABLED, style="TButton")
        self.stop_button.pack(pady=10, fill="x")

        ttk.Label(bottom_right_frame, text="Estatísticas Gerais:", font=('Segoe UI', 10, 'bold')).pack(pady=(20, 5), fill="x")
        self.show_stats_button = ttk.Button(bottom_right_frame, text="Ver Estatísticas", command=self.show_statistics_modal, style="TButton")
        self.show_stats_button.pack(pady=5, fill="x")


    def create_ping_cards(self, parent_frame):
        for widget in parent_frame.winfo_children():
            widget.destroy()
        self.ping_result_labels.clear()

        col = 0
        row = 0
        for name, target_address in self.ping_targets.items():
            card_frame = ttk.LabelFrame(parent_frame, text=name, padding="10", style="Card.TLabelframe")
            card_frame.grid(row=row, column=col, padx=8, pady=8, sticky="nsew")

            result_label = ttk.Label(card_frame, text="Aguardando...\nIP: N/A\nEnviados: 0, Recebidos: 0\nPerdidos: 0 (0%)", font=('Segoe UI', 9), justify="left", wraplength=150, style="Status.TLabel")
            result_label.pack(pady=5, fill="x")
            self.ping_result_labels.setdefault(target_address, result_label)

            ttk.Label(card_frame, text="Gráfico aqui", foreground="gray", font=('Segoe UI', 8)).pack(pady=(0,5))

            col += 1
            if col > 2:
                col = 0
                row += 1

    def load_network_info(self):
        threading.Thread(target=self._load_network_info_async, daemon=True).start()

    def _load_network_info_async(self):
        network_details = get_network_details()
        self.result_queue.put({"type": "network_details", "value": network_details})

    def update_network_info_ui(self, network_details):
        for widget in self.adapter_info_container.winfo_children():
            widget.destroy()
        self.network_info_frames.clear()

        self.public_ip_label.config(text=network_details["public_ipv4"])
        self.system_dns_label.config(text=network_details["system_dns_servers_str"])

        row_offset = 0
        if network_details["adapters"]:
            sorted_adapter_names = sorted(network_details["adapters"].keys()) 

            for adapter_name in sorted_adapter_names:
                info = network_details["adapters"].get(adapter_name)
                if info:
                    adapter_frame = ttk.LabelFrame(self.adapter_info_container, text=adapter_name, padding="8", style="TLabelframe")
                    adapter_frame.grid(row=row_offset, column=0, columnspan=2, sticky="ew", pady=5)
                    self.network_info_frames.setdefault(adapter_name, adapter_frame)

                    ttk.Label(adapter_frame, text="IPv4:", font=('Segoe UI', 9, 'bold')).grid(row=0, column=0, sticky="nw", padx=5, pady=2)
                    ttk.Label(adapter_frame, text=info.get("ipv4", "N/A"), font=('Segoe UI', 9), wraplength=350, justify="left").grid(row=0, column=1, sticky="nw", padx=5, pady=2)

                    ttk.Label(adapter_frame, text="IPv6:", font=('Segoe UI', 9, 'bold')).grid(row=1, column=0, sticky="nw", padx=5, pady=2)
                    ttk.Label(adapter_frame, text=info.get("ipv6", "N/A"), font=('Segoe UI', 9), wraplength=350, justify="left").grid(row=1, column=1, sticky="nw", padx=5, pady=2)

                    ttk.Label(adapter_frame, text="Gateway:", font=('Segoe UI', 9, 'bold')).grid(row=2, column=0, sticky="nw", padx=5, pady=2)
                    ttk.Label(adapter_frame, text=info.get("gateway", "N/A"), font=('Segoe UI', 9), wraplength=350, justify="left").grid(row=2, column=1, sticky="nw", padx=5, pady=2)
                    
                    ttk.Label(adapter_frame, text="Status:", font=('Segoe UI', 9, 'bold')).grid(row=3, column=0, sticky="nw", padx=5, pady=2)
                    ttk.Label(adapter_frame, text=info.get("status", "N/A"), font=('Segoe UI', 9), wraplength=350, justify="left").grid(row=3, column=1, sticky="nw", padx=5, pady=2)

                    ttk.Label(adapter_frame, text="Velocidade:", font=('Segoe UI', 9, 'bold')).grid(row=4, column=0, sticky="nw", padx=5, pady=2)
                    ttk.Label(adapter_frame, text=info.get("speed", "N/A"), font=('Segoe UI', 9), wraplength=350, justify="left").grid(row=4, column=1, sticky="nw", padx=5, pady=2)

                    adapter_frame.grid_columnconfigure(1, weight=1) 
                    row_offset += 1 
        else:
            ttk.Label(self.adapter_info_container, text="Nenhum adaptador de rede com IP encontrado.", font=('Segoe UI', 10), foreground=self.error_color).pack(pady=10)

    def start_ping(self):
        self.running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.ping_history.clear() 
        self.current_ping_stats = {target: {"sent": 0, "received": 0, "lost": 0} for target in self.ping_targets.values()} # Initialize
        self.overall_statistics_content = "Nenhum teste realizado." 
        
        for label in self.ping_result_labels.values():
            label.config(text="Aguardando...\nIP: N/A\nEnviados: 0, Recebidos: 0\nPerdidos: 0 (0%)", foreground=self.text_color) 
            
        self.ping_thread = threading.Thread(target=self._ping_loop, daemon=True)
        self.ping_thread.start()

    def stop_ping(self):
        self.running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.generate_overall_statistics()

    def _ping_loop(self):
        while self.running:
            for name, target_address in self.ping_targets.items():
                result = ping_address(target_address)
                result['target_name'] = name 
                result['target_address'] = target_address
                self.ping_history.append(result)
                
                # Update accumulated stats for current display
                self.current_ping_stats[target_address]["sent"] += result.get("sent", 0)
                self.current_ping_stats[target_address]["received"] += result.get("received", 0)
                self.current_ping_stats[target_address]["lost"] += result.get("lost", 0)

                # Send only the latest RTT and resolved IP, but use accumulated counts
                # Re-calculate loss_percent based on accumulated stats
                accumulated_sent = self.current_ping_stats[target_address]["sent"]
                accumulated_lost = self.current_ping_stats[target_address]["lost"]
                accumulated_loss_percent = (accumulated_lost / accumulated_sent * 100) if accumulated_sent > 0 else 0
                if accumulated_sent == 0 and accumulated_lost == 0:
                    accumulated_loss_percent = 0

                display_value = {
                    "rtt": result["rtt"], # Latest RTT
                    "resolved_ip": result["resolved_ip"], # Latest resolved IP
                    "sent": accumulated_sent,
                    "received": self.current_ping_stats[target_address]["received"],
                    "lost": accumulated_lost,
                    "loss_percent": accumulated_loss_percent,
                    "status": result["status"] # Latest status
                }
                self.result_queue.put({"type": "ping_result", "target": target_address, "value": display_value})
            time.sleep(self.ping_interval_seconds)

    def process_queue(self):
        try:
            while True:
                item = self.result_queue.get_nowait()
                if item["type"] == "network_details":
                    self.update_network_info_ui(item["value"])
                elif item["type"] == "ping_result":
                    target = item["target"]
                    value = item["value"] # This 'value' now contains accumulated counts
                    if target in self.ping_result_labels:
                        resolved_ip_display = value.get('resolved_ip')
                        if not re.match(r'^[\d\.:a-fA-F]+$', self.ping_targets.get(target, '')): # Check if target was a hostname
                            if re.match(r'^[\d\.:a-fA-F]+$', resolved_ip_display or ''): # And resolved_ip is actually an IP
                                pass 
                            else:
                                resolved_ip_display = "N/A" 
                        else: # If target was an IP
                            if not re.match(r'^[\d\.:a-fA-F]+$', resolved_ip_display or ''):
                                resolved_ip_display = "N/A" 
                        
                        display_text = (
                            f"Ping: {value.get('rtt', 'N/A')}\n"
                            f"IP: {resolved_ip_display}\n"
                            f"Enviados: {value.get('sent', 0)}, Recebidos: {value.get('received', 0)}\n"
                            f"Perdidos: {value.get('lost', 0)} ({value.get('loss_percent', 0):.1f}%)" 
                        )
                        self.ping_result_labels.get(target).config(text=display_text)
                        
                        status = value.get('status')
                        if status == "Sucesso":
                            self.ping_result_labels.get(target).config(foreground=self.success_color)
                        elif status == "Tempo limite" or status == "Host não encontrado":
                            self.ping_result_labels.get(target).config(foreground=self.warning_color)
                        elif status == "Falha desconhecida" or "Erro:" in status:
                             self.ping_result_labels.get(target).config(foreground=self.error_color)
                        else:
                            self.ping_result_labels.get(target).config(foreground=self.text_color) 
        except Empty:
            pass
        finally:
            self.master.after(100, self.process_queue)

    def generate_overall_statistics(self):
        stats_output = "--- Estatísticas Gerais ---\n"
        if not self.ping_history:
            stats_output += "Nenhum teste realizado.\n"
        else:
            aggregated_stats = {}
            for entry in self.ping_history:
                target = entry.get('target_name')
                if target:
                    stats = aggregated_stats.setdefault(target, {"sent": 0, "received": 0, "lost": 0, "rtts": []})
                    stats["sent"] += entry.get("sent", 0)
                    stats["received"] += entry.get("received", 0)
                    stats["lost"] += entry.get("lost", 0)
                    rtt_str = entry.get("rtt", "N/A")
                    if rtt_str not in ("N/A", "Tempo limite", "Host não encontrado", "Falha desconhecida", "Erro:"):
                        match = re.search(r'(\d+)', rtt_str)
                        if match:
                            stats["rtts"].append(int(match.group(1)))

            for target, stats in aggregated_stats.items():
                sent = stats.get("sent", 0)
                received = stats.get("received", 0)
                lost = stats.get("lost", 0)
                
                loss_percent = (lost / sent * 100) if sent > 0 else 0
                if sent == 0 and lost == 0: 
                    loss_percent = 0

                rtts = stats.get("rtts", [])
                min_rtt = f"{min(rtts)}ms" if rtts else "N/A"
                max_rtt = f"{max(rtts)}ms" if rtts else "N/A"
                avg_rtt = f"{sum(rtts) / len(rtts):.1f}ms" if rtts else "N/A"

                stats_output += (
                    f"\n{target} ({received}/{sent}):\n"
                    f"  Perda: {loss_percent:.1f}%\n"
                    f"  RTT Mín: {min_rtt}, Máx: {max_rtt}, Média: {avg_rtt}\n"
                )
            
            stats_output += "\n--- Fim das Estatísticas ---\n"
        self.overall_statistics_content = stats_output 

    def show_statistics_modal(self):
        modal_window = tk.Toplevel(self.master)
        modal_window.title("Estatísticas Gerais de Ping")
        modal_window.geometry("500x400")
        modal_window.transient(self.master) 
        modal_window.grab_set() 

        self.master.update_idletasks() 
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (modal_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (modal_window.winfo_height() // 2)
        modal_window.geometry(f"+{x}+{y}")
        
        modal_window.configure(bg=self.background_color)

        text_widget = tk.Text(modal_window, wrap="word", font=('Consolas', 10), bg=self.background_color, fg=self.text_color, borderwidth=0, padx=10, pady=10)
        text_widget.pack(expand=True, fill="both")
        
        scrollbar = ttk.Scrollbar(text_widget, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")

        text_widget.insert(tk.END, self.overall_statistics_content)
        text_widget.config(state=tk.DISABLED) 

        close_button = ttk.Button(modal_window, text="Fechar", command=modal_window.destroy, style="TButton")
        close_button.pack(pady=10)

        modal_window.protocol("WM_DELETE_WINDOW", modal_window.destroy) 
        modal_window.wait_window(modal_window) 


# --- Main Execution ---
if __name__ == "__main__":
    open(LOG_FILE, "w").close() 
    log_message("Aplicação iniciada.")
    root = tk.Tk()
    app = DNSPingApp(root)
    root.mainloop()
    log_message("Aplicação encerrada.")