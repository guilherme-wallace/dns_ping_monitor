import customtkinter as ctk
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
from fpdf import FPDF

# --- Configuração de Logging ---
LOG_FILE = "network_monitor_log.txt"

def log_message(message):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {message}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(log_entry)
    print(log_entry.strip())

# --- 1. Funções de Obtenção de Informações de Rede ---

def normalize_mac(mac_str):
    if mac_str:
        return mac_str.replace(':', '').replace('-', '').upper()
    return ""

def get_interface_friendly_names_windows_v6():
    mac_to_details_map = {}
    if sys.platform == "win32":
        try:
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
    system_dns_str = " || ".join(system_dns_servers) if system_dns_servers else "N/A"
    
    mac_to_details_map = get_interface_friendly_names_windows_v6()

    all_gateways = {}
    try:
        gws = netifaces.gateways()
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

    for iface_name in netifaces.interfaces():
        display_name = iface_name.replace('{', '').replace('}', '').strip()

        netifaces_mac = None
        if netifaces.AF_LINK in netifaces.ifaddresses(iface_name):
            for link in netifaces.ifaddresses(iface_name)[netifaces.AF_LINK]:
                if 'addr' in link:
                    netifaces_mac = normalize_mac(link['addr'])
                    break
        
        adapter_details = None
        if netifaces_mac and netifaces_mac in mac_to_details_map:
            adapter_details = mac_to_details_map[netifaces_mac]
            display_name = adapter_details["description"]
        else:
            pass

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

        if netifaces.AF_INET6 in netifaces.ifaddresses(iface_name):
            for link in netifaces.ifaddresses(iface_name)[netifaces.AF_INET6]:
                if 'addr' in link and not link['addr'].startswith('fe80::') and link['addr'] != '::1':
                    info["ipv6_addresses"].append(link['addr'].split('%')[0])

        if info["ipv4_addresses"] or info["ipv6_addresses"] or info["default_gateways"]:
            formatted_info[display_name] = {
                "ipv4": ", ".join(info["ipv4_addresses"]) if info["ipv4_addresses"] else "N/A",
                "ipv6": ", ".join(info["ipv6_addresses"]) if info["ipv6_addresses"] else "N/A",
                "dns": " || ".join(info["dns_servers"]) if info["dns_servers"] else "N/A",
                "gateway": ", ".join(info["default_gateways"]) if info["default_gateways"] else "N/A",
                "status": adapter_details["status"] if adapter_details else "N/A",
                "speed": adapter_details["speed"] if adapter_details else "N/A"
            }
        else:
            pass

    public_ip = get_public_ip() 

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

# Função para realizar consulta DNS com dnspython e medir latência
def perform_dns_query_with_latency(target_address, dns_servers=None):
    query_time_ms = "N/A"
    resolved_ips = []
    server_used = "N/A"
    
    resolver = dns.resolver.Resolver()
    if dns_servers:
        resolver.nameservers = dns_servers
    
    start_time = time.perf_counter()
    try:
        answers = resolver.resolve(target_address, 'A')
        end_time = time.perf_counter()
        query_time_ms = f"{(end_time - start_time) * 1000:.2f}ms"
        
        for rdata in answers:
            resolved_ips.append(str(rdata))
        
        if resolver.nameservers:
            server_used = resolver.nameservers[0]
            
    except dns.resolver.NXDOMAIN:
        resolved_ips.append("Domínio não encontrado")
    except dns.resolver.Timeout:
        resolved_ips.append("Tempo limite da consulta DNS")
    except Exception as e:
        resolved_ips.append(f"Erro na consulta DNS: {e}")
        
    return {
        "query_time": query_time_ms,
        "resolved_ips": resolved_ips,
        "server_used": server_used
    }

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

def perform_nslookup(target_address):
    try:
        command = ["nslookup", target_address]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5,
            encoding='utf-8',
            errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        return result.stdout if result.stdout else "Não foi possível obter informações de nslookup."
    except subprocess.TimeoutExpired:
        return "Tempo limite excedido ao executar nslookup."
    except FileNotFoundError:
        return "Comando 'nslookup' não encontrado. Certifique-se de que está no PATH do sistema."
    except Exception as e:
        return f"Erro ao executar nslookup: {e}"

# --- 3. Classe da Aplicação GUI ---
class NetworkMonitorApp:
    def __init__(self, master):
        self.master = master
        master.title("Monitor de Latência de Rede")
        master.geometry("900x750")
        master.resizable(True, True)

        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.ping_interval_seconds = 2 

        self.running = False
        self.ping_thread = None
        self.result_queue = Queue()
        self.ping_history = []
        self.current_ping_stats = {}

        self.network_info_frames = {} 
        self.ping_result_labels = {} 
        self.ping_dns_buttons = {}
        self.overall_statistics_content = "Nenhum teste realizado. \n AVISO: O ping deve ser iniciado e finalizado para gerar estatísticas."
        self.system_dns_servers_at_load = "N/A"
        self.last_network_details = {}

        self.ping_targets = {
            "DNS Google (8.8.8.8)": "8.8.8.8",
            "DNS Cloudflare (1.1.1.1)": "1.1.1.1",
            "DNS OpenDNS (208.67.222.222)": "208.67.222.222",
            "google.com": "google.com",
            "youtube.com": "youtube.com", 
            "facebook.com": "facebook.com",
            "amazon.com": "amazon.com",
            "microsoft.com": "microsoft.com",
            "www.terra.com.br": "www.terra.com.br",
        }

        self.setup_ui()
        self.load_network_info() 
        self.process_queue() 

    def setup_ui(self):
        self.app_scroll_frame = ctk.CTkScrollableFrame(self.master, corner_radius=0, fg_color="transparent")
        self.app_scroll_frame.pack(fill="both", expand=True, padx=0, pady=0)

        main_frame = ctk.CTkFrame(self.app_scroll_frame)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        main_frame.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        main_frame.grid_rowconfigure(0, weight=0)
        main_frame.grid_rowconfigure(1, weight=0)
        main_frame.grid_rowconfigure(2, weight=1)
        main_frame.grid_rowconfigure(3, weight=0)

        self.top_info_main_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        self.top_info_main_frame.grid(row=0, column=0, columnspan=2, pady=15, padx=15, sticky="ew")

        ctk.CTkLabel(self.top_info_main_frame, text="Endereço IPv4 Público:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=0, column=0, sticky="nw", pady=5, padx=10)
        self.public_ip_label = ctk.CTkLabel(self.top_info_main_frame, text="Carregando...", font=ctk.CTkFont(size=16), wraplength=400, justify="left")
        self.public_ip_label.grid(row=0, column=1, sticky="nw", pady=5, padx=10)

        ctk.CTkLabel(self.top_info_main_frame, text="Servidores DNS do Sistema:", font=ctk.CTkFont(size=16, weight="bold")).grid(row=1, column=0, sticky="nw", pady=5, padx=10)
        self.system_dns_label = ctk.CTkLabel(self.top_info_main_frame, text="Carregando...", font=ctk.CTkFont(size=16), wraplength=400, justify="left")
        self.system_dns_label.grid(row=1, column=1, sticky="nw", pady=5, padx=10)
        
        self.show_adapters_button = ctk.CTkButton(self.top_info_main_frame, text="Ver Adaptadores de Rede", 
                                                  command=self.show_network_adapters_modal, 
                                                  font=ctk.CTkFont(size=13, weight="bold"), corner_radius=8)
        self.show_adapters_button.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="ew")

        add_target_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        add_target_frame.grid(row=1, column=0, columnspan=2, pady=10, padx=15, sticky="ew")
        add_target_frame.grid_columnconfigure(0, weight=1)
        add_target_frame.grid_columnconfigure(1, weight=0)

        ctk.CTkLabel(add_target_frame, text="Adicionar novo alvo de Ping (IP ou Hostname):", font=ctk.CTkFont(size=15, weight="bold")).grid(row=0, column=0, columnspan=2, padx=10, pady=(10, 5), sticky="w")
        self.new_target_entry = ctk.CTkEntry(add_target_frame, placeholder_text="Ex: 192.168.1.1 ou google.com", font=ctk.CTkFont(size=15), corner_radius=8)
        self.new_target_entry.grid(row=1, column=0, padx=10, pady=5, sticky="ew")
        self.add_target_button = ctk.CTkButton(add_target_frame, text="Adicionar Alvo", command=self.add_new_ping_target, font=ctk.CTkFont(size=15, weight="bold"), corner_radius=8)
        self.add_target_button.grid(row=1, column=1, padx=10, pady=5, sticky="e")

        self.ping_cards_container_frame = ctk.CTkFrame(main_frame, corner_radius=10)
        self.ping_cards_container_frame.grid(row=2, column=0, columnspan=2, padx=15, pady=10, sticky="nsew")
        self.ping_cards_container_frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.ping_cards_container_frame, text="Resultados de Ping", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(10, 5), padx=10, anchor="w")

        self.ping_cards_frame = ctk.CTkFrame(self.ping_cards_container_frame, fg_color="transparent")
        self.ping_cards_frame.pack(fill="both", expand=True, padx=10, pady=10)
        for i in range(3):
            self.ping_cards_frame.grid_columnconfigure(i, weight=1)

        self.create_ping_cards(self.ping_cards_frame)

        bottom_buttons_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        bottom_buttons_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky="ew")
        bottom_buttons_frame.grid_columnconfigure((0,1,2), weight=1)

        self.start_button = ctk.CTkButton(bottom_buttons_frame, text="INICIAR TESTE", command=self.start_ping, font=ctk.CTkFont(size=16, weight="bold"), corner_radius=8)
        self.start_button.grid(row=0, column=0, padx=10, pady=5, sticky="e")

        self.stop_button = ctk.CTkButton(bottom_buttons_frame, text="PARAR TESTE", command=self.stop_ping, state="disabled", font=ctk.CTkFont(size=16, weight="bold"), corner_radius=8)
        self.stop_button.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        self.show_stats_button = ctk.CTkButton(bottom_buttons_frame, text="Ver Estatísticas", command=self.show_statistics_modal, font=ctk.CTkFont(size=16, weight="bold"), corner_radius=8)
        self.show_stats_button.grid(row=0, column=2, padx=10, pady=5, sticky="w")

    def create_ping_cards(self, parent_frame):
        for widget in parent_frame.winfo_children():
            widget.destroy()
        self.ping_result_labels.clear()
        self.ping_dns_buttons.clear()

        col = 0
        row = 0
        for name, target_address in self.ping_targets.items():
            card_frame = ctk.CTkFrame(parent_frame, corner_radius=10)
            card_frame.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")

            ctk.CTkLabel(card_frame, text=name, font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(10, 5), padx=10, anchor="w")

            result_label = ctk.CTkLabel(card_frame, text="Aguardando...\nIP: N/A\nEnviados: 0, Recebidos: 0\nPerdidos: 0 (0%)", 
                                        font=ctk.CTkFont(size=15), justify="left", wraplength=200)
            result_label.pack(pady=(0, 5), padx=10, fill="x")
            self.ping_result_labels[target_address] = result_label

            dns_button = ctk.CTkButton(card_frame, text="DNS utilizado", 
                                       command=lambda t=target_address: self.show_nslookup_modal(t),
                                       font=ctk.CTkFont(size=12), corner_radius=8, state="disabled")
            dns_button.pack(pady=(0, 10), padx=10, fill="x")
            self.ping_dns_buttons[target_address] = dns_button

            col += 1
            if col > 2:
                col = 0
                row += 1
        
        for i in range(3):
            parent_frame.grid_columnconfigure(i, weight=1)

    def add_new_ping_target(self):
        new_target = self.new_target_entry.get().strip()
        if not new_target:
            self.show_info_modal("Erro", "O campo de alvo de ping está vazio.")
            log_message("Campo de alvo de ping vazio.")
            return

        if new_target in self.ping_targets.values():
            self.show_info_modal("Aviso", f"O alvo '{new_target}' já está na lista de monitoramento.")
            log_message(f"Alvo '{new_target}' já existe ou é inválido.")
            return
            
        friendly_name = f"Alvo Personalizado ({new_target})"
        counter = 1
        original_friendly_name = friendly_name
        while friendly_name in self.ping_targets:
            friendly_name = f"{original_friendly_name} #{counter}"
            counter += 1

        self.ping_targets[friendly_name] = new_target
        self.current_ping_stats[new_target] = {"sent": 0, "received": 0, "lost": 0}
        self.create_ping_cards(self.ping_cards_frame)
        self.new_target_entry.delete(0, ctk.END)
        self.show_info_modal("Sucesso", f"Novo alvo de ping adicionado: '{friendly_name}'")
        log_message(f"Novo alvo de ping adicionado: {friendly_name} -> {new_target}")

    def load_network_info(self):
        threading.Thread(target=self._load_network_info_async, daemon=True).start()

    def _load_network_info_async(self):
        network_details = get_network_details()
        self.result_queue.put({"type": "network_details", "value": network_details})

    def update_network_info_ui(self, network_details):
        self.last_network_details = network_details 

        self.public_ip_label.configure(text=network_details["public_ipv4"])
        self.system_dns_label.configure(text=network_details["system_dns_servers_str"])
        self.system_dns_servers_at_load = network_details["system_dns_servers_str"]

    def show_network_adapters_modal(self):
        modal_window = ctk.CTkToplevel(self.master)
        modal_window.title("Detalhes dos Adaptadores de Rede")
        modal_window.geometry("800x600")
        modal_window.transient(self.master) 
        modal_window.grab_set() 

        self.master.update_idletasks() 
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (modal_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (modal_window.winfo_height() // 2)
        modal_window.geometry(f"+{x}+{y}")

        modal_scroll_frame = ctk.CTkScrollableFrame(modal_window, corner_radius=8)
        modal_scroll_frame.pack(expand=True, fill="both", padx=10, pady=10)
        modal_scroll_frame.grid_columnconfigure(0, weight=1)
        modal_scroll_frame.grid_columnconfigure(1, weight=1)

        network_details = self.last_network_details 
        
        row_count = 0
        col_count = 0
        max_cols = 2 

        if network_details.get("adapters"):
            sorted_adapter_names = sorted(network_details["adapters"].keys()) 

            for adapter_name in sorted_adapter_names:
                info = network_details["adapters"].get(adapter_name)
                if info:
                    adapter_frame = ctk.CTkFrame(modal_scroll_frame, corner_radius=8)
                    adapter_frame.grid(row=row_count, column=col_count, sticky="nsew", padx=5, pady=5)

                    ctk.CTkLabel(adapter_frame, text=adapter_name, font=ctk.CTkFont(size=13, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="nw", padx=5, pady=(5,0))
                    
                    ctk.CTkLabel(adapter_frame, text="IPv4:", font=ctk.CTkFont(size=11, weight="bold")).grid(row=1, column=0, sticky="nw", padx=5, pady=2)
                    ctk.CTkLabel(adapter_frame, text=info.get("ipv4", "N/A"), font=ctk.CTkFont(size=11), wraplength=150, justify="left").grid(row=1, column=1, sticky="nw", padx=5, pady=2)

                    ctk.CTkLabel(adapter_frame, text="IPv6:", font=ctk.CTkFont(size=11, weight="bold")).grid(row=2, column=0, sticky="nw", padx=5, pady=2)
                    ctk.CTkLabel(adapter_frame, text=info.get("ipv6", "N/A"), font=ctk.CTkFont(size=11), wraplength=150, justify="left").grid(row=2, column=1, sticky="nw", padx=5, pady=2)

                    ctk.CTkLabel(adapter_frame, text="Gateway:", font=ctk.CTkFont(size=11, weight="bold")).grid(row=3, column=0, sticky="nw", padx=5, pady=2)
                    ctk.CTkLabel(adapter_frame, text=info.get("gateway", "N/A"), font=ctk.CTkFont(size=11), wraplength=150, justify="left").grid(row=3, column=1, sticky="nw", padx=5, pady=2)
                    
                    ctk.CTkLabel(adapter_frame, text="Status:", font=ctk.CTkFont(size=11, weight="bold")).grid(row=4, column=0, sticky="nw", padx=5, pady=2)
                    ctk.CTkLabel(adapter_frame, text=info.get("status", "N/A"), font=ctk.CTkFont(size=11), wraplength=150, justify="left").grid(row=4, column=1, sticky="nw", padx=5, pady=2)

                    ctk.CTkLabel(adapter_frame, text="Velocidade:", font=ctk.CTkFont(size=11, weight="bold")).grid(row=5, column=0, sticky="nw", padx=5, pady=2)
                    ctk.CTkLabel(adapter_frame, text=info.get("speed", "N/A"), font=ctk.CTkFont(size=11), wraplength=150, justify="left").grid(row=5, column=1, sticky="nw", padx=5, pady=2)

                    adapter_frame.grid_columnconfigure(1, weight=1)

                    col_count += 1
                    if col_count >= max_cols:
                        col_count = 0
                        row_count += 1
        else:
            ctk.CTkLabel(modal_scroll_frame, text="Nenhum adaptador de rede com IP encontrado.", font=ctk.CTkFont(size=14), text_color="red").pack(pady=10)

        close_button = ctk.CTkButton(modal_window, text="Fechar", command=modal_window.destroy, corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"))
        close_button.pack(pady=10)

        modal_window.protocol("WM_DELETE_WINDOW", modal_window.destroy) 
        modal_window.wait_window(modal_window)

    def start_ping(self):
        self.running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.ping_history.clear() 
        self.current_ping_stats = {target: {"sent": 0, "received": 0, "lost": 0} for target in self.ping_targets.values()} 
        self.overall_statistics_content = "Nenhum teste realizado. \n AVISO: O ping deve ser iniciado e finalizado para gerar estatísticas." 
        
        for target_address, label in self.ping_result_labels.items():
            label.configure(text="Aguardando...\nIP: N/A\nEnviados: 0, Recebidos: 0\nPerdidos: 0 (0%)") 
            self.ping_dns_buttons[target_address].configure(state="disabled")
            
        self.ping_thread = threading.Thread(target=self._ping_loop, daemon=True)
        self.ping_thread.start()

    def stop_ping(self):
        self.running = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.generate_overall_statistics()

    def _ping_loop(self):
        while self.running:
            for name, target_address in list(self.ping_targets.items()):
                result = ping_address(target_address)
                result['target_name'] = name 
                result['target_address'] = target_address
                self.ping_history.append(result)
                
                is_hostname = not re.match(r'^[\d\.:a-fA-F]+$', target_address)

                self.current_ping_stats[target_address]["sent"] += result.get("sent", 0)
                self.current_ping_stats[target_address]["received"] += result.get("received", 0)
                self.current_ping_stats[target_address]["lost"] += result.get("lost", 0)

                accumulated_sent = self.current_ping_stats[target_address]["sent"]
                accumulated_lost = self.current_ping_stats[target_address]["lost"]
                accumulated_loss_percent = (accumulated_lost / accumulated_sent * 100) if accumulated_sent > 0 else 0
                if accumulated_sent == 0 and accumulated_lost == 0:
                    accumulated_loss_percent = 0

                display_value = {
                    "rtt": result["rtt"],
                    "resolved_ip": result["resolved_ip"],
                    "sent": accumulated_sent,
                    "received": self.current_ping_stats[target_address]["received"],
                    "lost": accumulated_lost,
                    "loss_percent": accumulated_loss_percent,
                    "status": result["status"],
                    "is_hostname": is_hostname,
                    "system_dns_info": self.system_dns_servers_at_load
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
                    value = item["value"]
                    if target in self.ping_result_labels:
                        resolved_ip_display = value.get('resolved_ip')
                        is_hostname = value.get('is_hostname', False)
                        system_dns_info = value.get('system_dns_info', 'N/A')

                        if is_hostname:
                            if not re.match(r'^[\d\.:a-fA-F]+$', resolved_ip_display or ''):
                                resolved_ip_display = "N/A" 
                        else:
                            if not re.match(r'^[\d\.:a-fA-F]+$', resolved_ip_display or ''):
                                resolved_ip_display = "N/A" 
                        
                        display_text = (
                            f"Ping: {value.get('rtt', 'N/A')}\n"
                            f"IP: {resolved_ip_display}\n"
                            f"Enviados: {value.get('sent', 0)}, Recebidos: {value.get('received', 0)}\n"
                            f"Perdidos: {value.get('lost', 0)} ({value.get('loss_percent', 0):.1f}%)" 
                        )
                        if is_hostname:
                            self.ping_dns_buttons[target].configure(state="normal")
                        else:
                            self.ping_dns_buttons[target].configure(state="disabled")

                        self.ping_result_labels.get(target).configure(text=display_text)
                        
                        status = value.get('status')
                        if status == "Sucesso":
                            self.ping_result_labels.get(target).configure(text_color="green")
                        elif status == "Tempo limite" or status == "Host não encontrado":
                            self.ping_result_labels.get(target).configure(text_color="orange")
                        elif status == "Falha desconhecida" or "Erro:" in status:
                             self.ping_result_labels.get(target).configure(text_color="red")
                        else:
                            self.ping_result_labels.get(target).configure(text_color=ctk.get_appearance_mode())
        except Empty:
            pass
        finally:
            self.master.after(100, self.process_queue)

    def generate_overall_statistics(self):
        stats_output = "--- Estatísticas Gerais ---\n"
        if not self.ping_history:
            stats_output += "Nenhum teste realizado. \n AVISO: O ping deve ser iniciado e finalizado para gerar estatísticas.\n"
        else:
            aggregated_stats = {}
            for entry in self.ping_history:
                target_address = entry.get('target_address')
                target_name = entry.get('target_name')
                if target_address:
                    stats = aggregated_stats.setdefault(target_address, {"name": target_name, "sent": 0, "received": 0, "lost": 0, "rtts": []})
                    stats["sent"] += entry.get("sent", 0)
                    stats["received"] += entry.get("received", 0)
                    stats["lost"] += entry.get("lost", 0)
                    rtt_str = entry.get("rtt", "N/A")
                    if rtt_str not in ("N/A", "Tempo limite", "Host não encontrado", "Falha desconhecida", "Erro:"):
                        match = re.search(r'(\d+)', rtt_str)
                        if match:
                            stats["rtts"].append(int(match.group(1)))

            sorted_targets = sorted(aggregated_stats.keys(), key=lambda k: aggregated_stats[k]["name"])

            for target_address in sorted_targets:
                stats = aggregated_stats[target_address]
                name = stats["name"]
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
                    f"\n{name} ({target_address}):\n"
                    f"  Pacotes Enviados: {sent}, Recebidos: {received}, Perdidos: {lost}\n"
                    f"  Perda: {loss_percent:.1f}%\n"
                    f"  RTT Mín: {min_rtt}, Máx: {max_rtt}, Média: {avg_rtt}\n"
                )
            
            stats_output += "\n--- Fim das Estatísticas ---\n"
        self.overall_statistics_content = stats_output 

    def show_info_modal(self, title, message):
        modal_window = ctk.CTkToplevel(self.master)
        modal_window.title(title)
        modal_window.geometry("400x180")
        modal_window.transient(self.master) 
        modal_window.grab_set() 

        self.master.update_idletasks() 
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (modal_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (modal_window.winfo_height() // 2)
        modal_window.geometry(f"+{x}+{y}")
        
        ctk.CTkLabel(modal_window, text=message, font=ctk.CTkFont(size=14), wraplength=350, justify="center").pack(expand=True, padx=10, pady=10)

        close_button = ctk.CTkButton(modal_window, text="OK", command=modal_window.destroy, corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"))
        close_button.pack(pady=10)

        modal_window.protocol("WM_DELETE_WINDOW", modal_window.destroy) 
        modal_window.wait_window(modal_window) 

    def show_nslookup_modal(self, target_address):
        modal_window = ctk.CTkToplevel(self.master)
        modal_window.title(f"Informações DNS para: {target_address}")
        modal_window.geometry("600x450")
        modal_window.transient(self.master) 
        modal_window.grab_set() 

        self.master.update_idletasks() 
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (modal_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (modal_window.winfo_height() // 2)
        modal_window.geometry(f"+{x}+{y}")

        loading_label = ctk.CTkLabel(modal_window, text="Carregando informações DNS...", font=ctk.CTkFont(size=16))
        loading_label.pack(expand=True, fill="both", padx=10, pady=10)
        
        text_widget = ctk.CTkTextbox(modal_window, wrap="word", font=('Consolas', 14), corner_radius=8)
        
        def _run_dns_info_and_update_modal():
            nslookup_output = perform_nslookup(target_address)
            
            full_dns_query_output = "--- Tempo de Consulta DNS ---\n"
            system_dns_servers_list = self.system_dns_servers_at_load.split(' || ')
            
            if system_dns_servers_list and system_dns_servers_list[0] != 'N/A':
                for dns_server in system_dns_servers_list:
                    dns_query_info = perform_dns_query_with_latency(target_address, [dns_server])
                    full_dns_query_output += (
                        f"  Servidor Utilizado: {dns_query_info['server_used']}\n"
                        f"  Tempo: {dns_query_info['query_time']}\n"
                        f"  IPs Resolvidos: {', '.join(dns_query_info['resolved_ips']) if dns_query_info['resolved_ips'] else 'N/A'}\n"
                        f"  \n---\n"
                    )
            else:
                full_dns_query_output += "  Servidores DNS do sistema não disponíveis para teste de latência.\n"
            
            full_output = f"{full_dns_query_output}\n--- nslookup ---\n{nslookup_output}"

            loading_label.destroy()
            text_widget.pack(expand=True, fill="both", padx=10, pady=10)
            text_widget.insert("end", full_output)
            text_widget.configure(state="disabled")

            close_button = ctk.CTkButton(modal_window, text="Fechar", command=modal_window.destroy, corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"))
            close_button.pack(pady=10)

        threading.Thread(target=_run_dns_info_and_update_modal, daemon=True).start()

        modal_window.protocol("WM_DELETE_WINDOW", modal_window.destroy) 
        modal_window.wait_window(modal_window)

    def generate_pdf_report(self):
        """
        Gera um relatório PDF com todas as informações da aplicação.
        """
        loading_modal = ctk.CTkToplevel(self.master)
        loading_modal.title("Gerando PDF")
        loading_modal.geometry("300x150")
        loading_modal.transient(self.master)
        loading_modal.grab_set()
        loading_label = ctk.CTkLabel(loading_modal, text="Gerando relatório PDF...\nIsso pode levar um momento.", font=ctk.CTkFont(size=14), wraplength=250, justify="center")
        loading_label.pack(expand=True, fill="both", padx=10, pady=10)
        
        def _generate_pdf_async():
            try:
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)

                pdf.set_font("Arial", "B", 20)
                pdf.cell(0, 10, "Relatório de Monitoramento de Rede", 0, 1, "C")
                pdf.ln(10)

                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Informações Gerais da Rede", 0, 1, "L")
                pdf.set_font("Arial", size=12)
                pdf.cell(0, 7, f"IP Público: {self.last_network_details.get('public_ipv4', 'N/A')}", 0, 1)
                pdf.cell(0, 7, f"Servidores DNS do Sistema: {self.last_network_details.get('system_dns_servers_str', 'N/A')}", 0, 1)
                pdf.ln(5)

                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Detalhes dos Adaptadores de Rede", 0, 1, "L")
                if self.last_network_details.get("adapters"):
                    for adapter_name, info in self.last_network_details["adapters"].items():
                        pdf.set_font("Arial", "B", 12)
                        pdf.cell(0, 7, f"Adaptador: {adapter_name}", 0, 1)
                        pdf.set_font("Arial", size=10)
                        pdf.cell(0, 5, f"  IPv4: {info.get('ipv4', 'N/A')}", 0, 1)
                        pdf.cell(0, 5, f"  IPv6: {info.get('ipv6', 'N/A')}", 0, 1)
                        pdf.cell(0, 5, f"  Gateway: {info.get('gateway', 'N/A')}", 0, 1)
                        pdf.cell(0, 5, f"  Status: {info.get('status', 'N/A')}", 0, 1)
                        pdf.cell(0, 5, f"  Velocidade: {info.get('speed', 'N/A')}", 0, 1)
                        pdf.ln(3)
                else:
                    pdf.set_font("Arial", size=12)
                    pdf.cell(0, 7, "Nenhum adaptador de rede encontrado.", 0, 1)
                pdf.ln(5)

                pdf.set_font("Arial", "B", 14)
                pdf.cell(0, 10, "Estatísticas de Ping", 0, 1, "L")
                pdf.set_font("Arial", size=12)
                if not self.ping_history:
                    pdf.cell(0, 7, "Nenhum teste de ping realizado.", 0, 1)
                else:
                    aggregated_stats = {}
                    for entry in self.ping_history:
                        target_address = entry.get('target_address')
                        target_name = entry.get('target_name')
                        if target_address:
                            stats = aggregated_stats.setdefault(target_address, {"name": target_name, "sent": 0, "received": 0, "lost": 0, "rtts": []})
                            stats["sent"] += entry.get("sent", 0)
                            stats["received"] += entry.get("received", 0)
                            stats["lost"] += entry.get("lost", 0)
                            rtt_str = entry.get("rtt", "N/A")
                            if rtt_str not in ("N/A", "Tempo limite", "Host não encontrado", "Falha desconhecida", "Erro:"):
                                match = re.search(r'(\d+)', rtt_str)
                                if match:
                                    stats["rtts"].append(int(match.group(1)))
                    
                    sorted_targets = sorted(aggregated_stats.keys(), key=lambda k: aggregated_stats[k]["name"])

                    for target_address in sorted_targets:
                        stats = aggregated_stats[target_address]
                        name = stats["name"]
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
                        
                        pdf.set_font("Arial", "B", 12)
                        pdf.cell(0, 7, f"Alvo: {name} ({target_address})", 0, 1)
                        pdf.set_font("Arial", size=10)
                        pdf.cell(0, 5, f"  Pacotes Enviados: {sent}, Recebidos: {received}, Perdidos: {lost}", 0, 1)
                        pdf.cell(0, 5, f"  Perda: {loss_percent:.1f}%", 0, 1)
                        pdf.cell(0, 5, f"  RTT Mín: {min_rtt}, Máx: {max_rtt}, Média: {avg_rtt}", 0, 1)
                        pdf.ln(3)

                from tkinter import filedialog
                file_path = filedialog.asksaveasfilename(defaultextension=".pdf",
                                                        filetypes=[("PDF files", "*.pdf")],
                                                        title="Salvar Relatório de Rede")
                if file_path:
                    pdf.output(file_path)
                    self.show_info_modal("PDF Gerado", f"Relatório salvo em:\n{file_path}")
                else:
                    self.show_info_modal("PDF Cancelado", "A geração do relatório PDF foi cancelada.")

            except Exception as e:
                self.show_info_modal("Erro ao Gerar PDF", f"Ocorreu um erro: {e}")
                log_message(f"Erro ao gerar PDF: {e}")
            finally:
                loading_modal.destroy()

        threading.Thread(target=_generate_pdf_async, daemon=True).start()


    def show_statistics_modal(self):
        modal_window = ctk.CTkToplevel(self.master)
        modal_window.title("Estatísticas Gerais de Ping")
        modal_window.geometry("800x650")
        modal_window.transient(self.master) 
        modal_window.grab_set() 

        self.master.update_idletasks() 
        x = self.master.winfo_x() + (self.master.winfo_width() // 2) - (modal_window.winfo_width() // 2)
        y = self.master.winfo_y() + (self.master.winfo_height() // 2) - (modal_window.winfo_height() // 2)
        modal_window.geometry(f"+{x}+{y}")
        
        text_widget = ctk.CTkTextbox(modal_window, wrap="word", font=('Consolas', 12), corner_radius=8)
        text_widget.pack(expand=True, fill="both", padx=10, pady=10)
        
        text_widget.insert("end", self.overall_statistics_content)
        text_widget.configure(state="disabled") 

        pdf_button = ctk.CTkButton(modal_window, text="Gerar Relatório PDF", command=self.generate_pdf_report, 
                                   corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"))
        pdf_button.pack(pady=(0, 10))

        close_button = ctk.CTkButton(modal_window, text="Fechar", command=modal_window.destroy, corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"))
        close_button.pack(pady=10)

        modal_window.protocol("WM_DELETE_WINDOW", modal_window.destroy) 
        modal_window.wait_window(modal_window) 


# --- Execução Principal ---
if __name__ == "__main__":
    open(LOG_FILE, "w").close() 
    log_message("Aplicação iniciada.")
    app = ctk.CTk()
    NetworkMonitorApp(app)
    app.mainloop()
    log_message("Aplicação encerrada.")
