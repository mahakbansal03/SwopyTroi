import nmap
import scapy.all as scapy
import requests
import time
import subprocess
import re
import socket
import ssl
import dns.resolver  # dnspython kütüphanesi
from ipwhois import IPWhois  # WHOIS sorgulama için
from bs4 import BeautifulSoup
from colorama import Fore, init
import signal
import sys
import urllib.request
import urllib.error
import concurrent.futures
import random
import json
from datetime import datetime
from urllib.parse import urlparse
import netifaces  # Ağ arayüzleri için
import speedtest  # Ağ hız testi için
import manuf  # MAC adresi üretici bilgisi için
import platform  # İşletim sistemi kontrolü için

# Initialize colorama for colored terminal output
init()

# Default credentials for modem login attempts
DEFAULT_CREDS = [
    ("admin", "admin"),          # General default
    ("admin", "password"),       # TP-Link, D-Link
    ("admin", "1234"),           # Some modems
    ("admin", ""),               # Empty password
    ("root", "root"),            # Some modems
    ("user", "user"),            # Some modems
    ("admin", "ttnet"),          # Turkish Telecom modems
    ("admin", "turktelekom"),    # Turkish Telecom modems
]

# Nmap scanner object
nm = nmap.PortScanner()

# MAC adresi üretici bilgisi için manuf nesnesi
mac_db = manuf.MacParser()

# Handle Ctrl+C for graceful exit
def signal_handler(sig, frame):
    print(Fore.MAGENTA + "\n\n[*] Exiting...")
    print(Fore.GREEN + "Thank you! Developed by JosephSpace (SW).")
    print(Fore.CYAN + "See you! 😊")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Wait for user to press 'S' to return to the main menu
def wait_for_return():
    while True:
        choice = input(Fore.YELLOW + "\nPress S to return to the main menu: ").upper()
        if choice == "S":
            break

# 1. Comprehensive Network Scan (ARP and Nmap Scan)
def network_scan(ip_range):
    print(Fore.YELLOW + "[*] Starting comprehensive network scan...")
    
    # Scan ARP table
    print(Fore.CYAN + "[*] Scanning ARP table...")
    try:
        arp_output = subprocess.check_output("arp -a", shell=True, text=True)
        print(Fore.GREEN + "[+] ARP Table:")
        print(arp_output)
    except subprocess.CalledProcessError:
        print(Fore.RED + "[-] Could not retrieve ARP table. Check OS compatibility.")

    # Scapy ARP Scan
    print(Fore.CYAN + "[*] Performing ARP scan with Scapy...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)
        print(Fore.GREEN + f"[+] Device: IP: {device['ip']}, MAC: {device['mac']}")

    # Nmap Ping Scan
    print(Fore.CYAN + "[*] Performing ping scan with Nmap...")
    try:
        nm.scan(hosts=ip_range, arguments='-sn')
        for host in nm.all_hosts():
            print(Fore.GREEN + f"[+] Device found: {host}")
    except Exception as e:
        print(Fore.RED + f"[-] Error during Nmap ping scan: {e}")
        wait_for_return()
        return devices

    # Nmap Detailed Port Scan with error handling
    print(Fore.CYAN + "[*] Performing detailed port scan with Nmap...")
    for host in nm.all_hosts():
        try:
            nm.scan(hosts=host, arguments='-p- --open -sV')
            print(Fore.YELLOW + f"\n[+] Device: {host}")
            if host in nm._scan_result.get('scan', {}):
                if 'tcp' in nm[host]:
                    for port in nm[host].all_tcp():
                        service = nm[host]['tcp'][port]['name']
                        state = nm[host]['tcp'][port]['state']
                        print(Fore.GREEN + f"    Port: {port}, State: {state}, Service: {service}")
                else:
                    print(Fore.RED + f"[-] No open TCP ports found for {host}")
            else:
                print(Fore.RED + f"[-] Host {host} not found in detailed scan results")
        except Exception as e:
            print(Fore.RED + f"[-] Error scanning host {host}: {e}")

    wait_for_return()
    return devices

# 2. Modem Firmware Update Check
def modem_firmware_check():
    print(Fore.YELLOW + "[*] Starting modem firmware check...")
    modem_ip = input(Fore.WHITE + "Please enter the modem IP address (e.g., 192.168.1.1): ")
    if not modem_ip:
        print(Fore.RED + "[-] Modem IP not specified. Using default: 192.168.1.1.")
        modem_ip = "192.168.1.1"

    print(Fore.CYAN + f"Modem IP: {modem_ip}")
    print(Fore.YELLOW + "[*] Trying default username and password combinations...")

    for username, password in DEFAULT_CREDS:
        print(Fore.CYAN + f"Trying Username: {username}, Password: {password}...")
        try:
            response = requests.get(f"http://{modem_ip}", auth=(username, password), timeout=1)
            if response.status_code == 200:
                print(Fore.GREEN + f"[+] Successfully accessed modem interface! Username: {username}, Password: {password}")
                print(Fore.YELLOW + "[*] Checking firmware version...")
                
                soup = BeautifulSoup(response.text, 'html.parser')
                firmware_version = None
                for text in soup.stripped_strings:
                    if "firmware" in text.lower() and "version" in text.lower():
                        firmware_version = text
                        break
                    elif re.search(r'\d+\.\d+\.\d+', text):
                        firmware_version = text
                        break
                
                if firmware_version:
                    print(Fore.GREEN + f"[+] Firmware Version: {firmware_version}")
                else:
                    print(Fore.RED + "[-] Firmware version not found. Please check the page manually.")
                wait_for_return()
                return True
            else:
                print(Fore.RED + f"[-] Access failed: {response.status_code}")
        except requests.exceptions.RequestException:
            print(Fore.RED + "[-] Could not connect to modem interface.")
        time.sleep(1)

    print(Fore.RED + "[-] Could not access with default credentials.")
    wait_for_return()
    return False

# 3. Website Analysis (Comprehensive)
def analyze_website():
    print(Fore.YELLOW + "[*] Starting website analysis...")
    url = input(Fore.WHITE + "Please enter the URL to analyze (e.g., https://example.com): ")
    if not url.startswith("http"):
        url = "https://" + url

    try:
        # Find IP address
        domain = urlparse(url).netloc
        ip_address = socket.gethostbyname(domain)
        print(Fore.GREEN + f"[+] IP Address: {ip_address}")

        # Fetch IP information using ipinfo.io
        print(Fore.YELLOW + "[*] Fetching IP information (ipinfo.io)...")
        try:
            r = requests.get("https://ipinfo.io/")
            if r.status_code != 200:
                print(Fore.RED + "[!] ipinfo.io server is offline!")
                wait_for_return()
                return

            country = requests.get(f"https://ipinfo.io/{ip_address}/country/").text.strip()
            city = requests.get(f"https://ipinfo.io/{ip_address}/city/").text.strip()
            region = requests.get(f"https://ipinfo.io/{ip_address}/region/").text.strip()
            postal = requests.get(f"https://ipinfo.io/{ip_address}/postal/").text.strip()
            timezone = requests.get(f"https://ipinfo.io/{ip_address}/timezone/").text.strip()
            org = requests.get(f"https://ipinfo.io/{ip_address}/org/").text.strip()
            loc = requests.get(f"https://ipinfo.io/{ip_address}/loc/").text.strip()

            print(Fore.GREEN + f"[+] Country: {country}")
            print(Fore.GREEN + f"[+] City: {city}")
            print(Fore.GREEN + f"[+] Region: {region}")
            print(Fore.GREEN + f"[+] Postal Code: {postal}")
            print(Fore.GREEN + f"[+] Timezone: {timezone}")
            print(Fore.GREEN + f"[+] Organization: {org}")
            print(Fore.GREEN + f"[+] Location (Latitude/Longitude): {loc}")
        except Exception as e:
            print(Fore.RED + f"[-] Could not fetch IP info: {e}")

        # Fetch server headers
        print(Fore.YELLOW + "[*] Fetching server headers...")
        response = requests.get(url, timeout=5)
        headers = response.headers
        print(Fore.GREEN + "[+] Server Headers:")
        for key, value in headers.items():
            print(Fore.CYAN + f"    {key}: {value}")

        # Server type
        server_type = headers.get('Server', 'Unknown')
        print(Fore.GREEN + f"[+] Server Type: {server_type}")

        # SSL Certificate Information
        print(Fore.YELLOW + "[*] Fetching SSL certificate information...")
        try:
            cert_response = requests.get(url, timeout=5, verify=True)
            cert = cert_response.raw.connection.sock.getpeercert()
            print(Fore.GREEN + f"[+] SSL Certificate Issuer: {cert.get('issuer', 'Unknown')}")
            print(Fore.GREEN + f"[+] Valid Until: {cert.get('notAfter', 'Unknown')}")
        except Exception:
            print(Fore.RED + "[-] Could not fetch SSL certificate information.")

        # Parse the page
        soup = BeautifulSoup(response.text, 'html.parser')

        # Analyze external connections
        print(Fore.YELLOW + "[*] Analyzing server connections...")
        external_connections = set()
        for link in soup.find_all(['a', 'img', 'script'], href=True):
            href = link['href']
            if href.startswith('http') and domain not in href:
                external_connections.add(urlparse(href).netloc)
        for link in soup.find_all(['a', 'img', 'script'], src=True):
            src = link['src']
            if src.startswith('http') and domain not in src:
                external_connections.add(urlparse(src).netloc)
        
        if external_connections:
            print(Fore.GREEN + "[+] External Server Connections:")
            for conn in external_connections:
                print(Fore.CYAN + f"    - {conn}")
        else:
            print(Fore.RED + "[-] No external server connections found.")

        # Look for admin panel (simplified version)
        print(Fore.YELLOW + "[*] Looking for admin panel...")
        admin_paths = ['/admin', '/login', '/wp-admin', '/administrator', '/dashboard']
        for path in admin_paths:
            try:
                admin_url = url.rstrip('/') + path
                admin_response = requests.get(admin_url, timeout=3)
                if admin_response.status_code == 200:
                    print(Fore.GREEN + f"[+] Possible admin panel found: {admin_url}")
                elif admin_response.status_code == 401 or admin_response.status_code == 403:
                    print(Fore.YELLOW + f"[*] Restricted access (possibly admin): {admin_url}")
            except requests.exceptions.RequestException:
                pass

        # Extract other data from the page
        print(Fore.YELLOW + "[*] Extracting other data from the page...")
        for text in soup.stripped_strings:
            if len(text) > 10:
                print(Fore.CYAN + f"    - {text}")

    except Exception as e:
        print(Fore.RED + f"[-] Error: {e}")
    
    wait_for_return()

# 4. Admin Panel Finder
class AdminFinder:
    def __init__(self, url, threads=10, timeout=3):
        self.url = self._format_url(url)
        self.threads = threads
        self.timeout = timeout
        self.found = []
        self.total = 0
        self.checked = 0
        self.user_agents = self._load_user_agents()

    def _format_url(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        if not url.endswith('/'):
            url += '/'
        return url
    
    def _get_paths(self):
        return [
            'admin/', 'admin/login', 'admin/login.php', 'wp-admin/', 'login.php', 
            'administrator/', 'admin/account.php', 'adminpanel/', 'cpanel/', 
            'login/', 'wp-login.php', 'administrator/index.php', 'admin/index.php',
            'panel/', 'admin1/', 'admin2/', 'admin.php', 'admin.html',
            'adminLogin/', 'admin_area/', 'panel-administracion/', 'instadmin/',
            'memberadmin/', 'administratorlogin/', 'adm/', 'account.asp', 
            'admin/account.asp', 'admin/index.asp', 'admin/login.asp', 'admin/admin.asp',
            'user/login', 'admin/user/login', 'user', 'user/admin', 'admin/user',
            'phpmyadmin/', 'phpmyadmin/index.php', 'phpMyAdmin/', 'phpMyAdmin/index.php',
            'webmail/', 'mail/', 'cpanel/', 'cp/', 'webmin/', 'plesk/',
            'signin/', 'sign-in/', 'sign_in/', 'sign-in.php', 'login.asp',
            'login.html', 'login.htm', 'login/', 'logon/', 'logon.php',
            'logon.asp', 'logon.html', 'signin.php', 'signin.html', 'signin.asp',
            'backend/', 'back-end/', 'back/', 'config/', 'configuration/',
            'settings/', 'setting/', 'setup/', 'configure/', 'dashboard/',
            'dash/', 'moderator/', 'mod/', 'webmaster/', 'mods/', 'supervisor/',
            'support/', 'staff/', 'cp/', 'cms/', 'cms/login', 'cms/admin/',
            'cms/admin/login', 'console/', 'console/login', 'console/admin/'
        ]
    
    def _load_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:95.0) Gecko/20100101 Firefox/95.0",
            "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36"
        ]
            
    def check_url(self, path):
        full_url = self.url + path
        try:
            request = urllib.request.Request(full_url)
            user_agent = random.choice(self.user_agents)
            request.add_header('User-Agent', user_agent)
            request.add_header('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8')
            request.add_header('Accept-Language', 'en-US,en;q=0.5')
            request.add_header('Referer', self.url)
            request.add_header('Cookie', 'session=test')
            
            response = urllib.request.urlopen(request, timeout=self.timeout)
            status_code = response.getcode()
            content = response.read(1024).decode('utf-8', errors='ignore')
            
            admin_indicators = [
                'username', 'password', 'admin', 'login', 'sign in', 'signin',
                'dashboard', 'cpanel', 'control panel', 'admin area', 'admin panel',
                'administration', 'login form', 'authentication', 'auth', 'authorize'
            ]
            
            title_indicators = [
                '<title>admin</title>', '<title>login</title>', 
                '<title>panel</title>', '<title>cpanel</title>',
                '<title>control panel</title>', '<title>dashboard</title>',
                '<title>administrator</title>'
            ]
            
            content_lower = content.lower()
            
            if 200 <= status_code < 300:
                if any(indicator in content_lower for indicator in admin_indicators) or \
                   any(indicator.lower() in content_lower for indicator in title_indicators):
                    self.found.append((full_url, "CONFIRMED"))
                    print(f"{Fore.GREEN}[+] CONFIRMED: {full_url} ({status_code}) - Admin panel content detected!")
                elif '<form' in content_lower and ('pass' in content_lower or 'user' in content_lower):
                    self.found.append((full_url, "PROBABLE"))
                    print(f"{Fore.BLUE}[+] PROBABLE: {full_url} ({status_code}) - Contains login form")
                else:
                    self.found.append((full_url, "WEAK"))
                    print(f"{Fore.CYAN}[+] POSSIBLE PANEL: {full_url} ({status_code})")
            
            elif status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location', '')
                if 'login' in redirect_url or 'admin' in redirect_url:
                    self.found.append((full_url, "REDIRECT"))
                    print(f"{Fore.YELLOW}[+] REDIRECT FOUND: {full_url} → {redirect_url}")
                
        except urllib.error.HTTPError as e:
            if e.code in [401, 403]:
                self.found.append((full_url, "ACCESS DENIED"))
                print(f"{Fore.YELLOW}[!] ACCESS DENIED: {full_url} ({e.code}) - Login may be required!")
        except Exception:
            pass
        finally:
            self.checked += 1
    
    def start_scan(self):
        paths = self._get_paths()
        self.total = len(paths)
        
        print(f"{Fore.BLUE}[*] Target: {self.url}")
        print(f"{Fore.BLUE}[*] Checking {self.total} potential admin panel paths...")
        print(f"{Fore.BLUE}[*] Using {self.threads} threads")
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_url, paths)
        
        self.scan_duration = time.time() - start_time
        
        print(f"\n{Fore.BLUE}[*] Scan completed. Duration: {self.scan_duration:.2f} seconds")
        
        if self.found:
            print("\n" + "="*60)
            print(f"{Fore.GREEN}[+] FOUND PANEL RESULTS:")
            print("="*60)
            
            confidence_levels = {"CONFIRMED": 1, "ACCESS DENIED": 2, "REDIRECT": 3, "PROBABLE": 4, "WEAK": 5}
            self.found.sort(key=lambda x: confidence_levels.get(x[1], 999))
            
            unique_urls = {}
            for url, confidence in self.found:
                if url in unique_urls and confidence_levels.get(unique_urls[url], 999) <= confidence_levels.get(confidence, 999):
                    continue
                unique_urls[url] = confidence
            
            sorted_results = sorted(unique_urls.items(), key=lambda x: confidence_levels.get(x[1], 999))
            
            for url, confidence in sorted_results:
                if confidence == "CONFIRMED":
                    print(f"{Fore.GREEN}[+++] {confidence}: {url}")
                elif confidence == "ACCESS DENIED":
                    print(f"{Fore.YELLOW}[++] {confidence}: {url}")
                elif confidence == "REDIRECT" or confidence == "PROBABLE":
                    print(f"{Fore.BLUE}[++] {confidence}: {url}")
                else:
                    print(f"{Fore.CYAN}[+] {confidence}: {url}")
            
            print("\n" + "="*60)
            print(f"{Fore.GREEN}Total found: {len(sorted_results)}")
            
            self.found = sorted_results
            self._save_results()
        else:
            print(f"\n{Fore.YELLOW}[!] No admin panels found.")

    def _save_results(self):
        filename = f"admin_panels_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            results_data = {
                "target": self.url,
                "scan_date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "total_found": len(self.found),
                "scan_duration_seconds": self.scan_duration,
                "results": []
            }
            
            for url, confidence in self.found:
                results_data["results"].append({
                    "url": url,
                    "confidence": confidence,
                    "discovery_time": datetime.now().strftime('%Y-%m-d %H:%M:%S')
                })
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results_data, f, ensure_ascii=False, indent=4)
            
            print(f"{Fore.GREEN}[+] Results saved to '{filename}' JSON file.")
        except Exception as e:
            print(f"{Fore.RED}[!] Error saving results: {str(e)}")

def admin_panel_finder():
    print(Fore.YELLOW + "[*] Starting Admin Panel Finder...")
    url = input(Fore.WHITE + "Please enter the target URL (e.g., https://example.com): ")
    finder = AdminFinder(url)
    finder.start_scan()
    wait_for_return()

# 5. IP Query (Updated with WHOIS)
def ip_query():
    print(Fore.YELLOW + "[*] Starting IP query...")
    ip = input(Fore.WHITE + "Please enter the target IP address: ")

    try:
        r = requests.get("https://ipinfo.io/", timeout=5)
        if r.status_code == 200:
            print(Fore.GREEN + "\n[+] Server Online!\n")
        else:
            print(Fore.RED + "\n[!] Server Offline!\n")
            wait_for_return()
            return
    except requests.exceptions.RequestException:
        print(Fore.RED + "\n[!] Server Offline!\n")
        wait_for_return()
        return

    try:
        country = requests.get(f"https://ipinfo.io/{ip}/country/").text.strip()
        city = requests.get(f"https://ipinfo.io/{ip}/city/").text.strip()
        region = requests.get(f"https://ipinfo.io/{ip}/region/").text.strip()
        postal = requests.get(f"https://ipinfo.io/{ip}/postal/").text.strip()
        timezone = requests.get(f"https://ipinfo.io/{ip}/timezone/").text.strip()
        org = requests.get(f"https://ipinfo.io/{ip}/org/").text.strip()
        loc = requests.get(f"https://ipinfo.io/{ip}/loc/").text.strip()

        print(Fore.GREEN + f"[+] IP: {ip}")
        print(Fore.GREEN + f"[+] Country: {country}")
        print(Fore.GREEN + f"[+] City: {city}")
        print(Fore.GREEN + f"[+] Region: {region}")
        print(Fore.GREEN + f"[+] Postal Code: {postal}")
        print(Fore.GREEN + f"[+] Timezone: {timezone}")
        print(Fore.GREEN + f"[+] Organization: {org}")
        print(Fore.GREEN + f"[+] Location (Latitude/Longitude): {loc}")

        # WHOIS Lookup
        print(Fore.YELLOW + "[*] Performing WHOIS lookup...")
        try:
            whois = IPWhois(ip)
            results = whois.lookup_rdap()
            print(Fore.GREEN + f"[+] WHOIS Information:")
            print(Fore.CYAN + f"    Network Name: {results.get('network', {}).get('name', 'Unknown')}")
            print(Fore.CYAN + f"    Organization: {results.get('network', {}).get('remarks', ['Unknown'])[0] if results.get('network', {}).get('remarks') else 'Unknown'}")
            print(Fore.CYAN + f"    Country: {results.get('network', {}).get('country', 'Unknown')}")
        except Exception as e:
            print(Fore.RED + f"[-] Could not fetch WHOIS information: {e}")

    except Exception as e:
        print(Fore.RED + f"[-] Could not fetch IP information: {e}")
    
    wait_for_return()

# 6. Wi-Fi Şifre Kırma (Gerçek Veri ile)
def wifi_password_cracker():
    print(Fore.YELLOW + "[*] Starting Wi-Fi Password Cracker...")
    print(Fore.RED + "[!] WARNING: This tool should only be used on networks you own or have explicit permission to test.")
    print(Fore.RED + "[!] Unauthorized access to Wi-Fi networks is illegal and can lead to serious legal consequences.")

    # İşletim sistemi kontrolü
    os_name = platform.system()
    if os_name != "Linux":
        print(Fore.RED + "[-] This module is only supported on Linux due to monitor mode requirements.")
        print(Fore.YELLOW + "[!] Please run this on a Linux system (e.g., Kali Linux) with a compatible Wi-Fi adapter.")
        wait_for_return()
        return

    # Wi-Fi arayüzünü kullanıcıdan al
    iface = input(Fore.WHITE + "Please enter your Wi-Fi interface (e.g., wlan0): ")
    if not iface:
        print(Fore.RED + "[-] Wi-Fi interface is required!")
        wait_for_return()
        return

    # Monitor moduna geçme
    print(Fore.YELLOW + "[*] Enabling monitor mode on interface {}...".format(iface))
    try:
        # Mevcut ağ bağlantılarını kapat
        subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
        # Monitor moduna geç
        subprocess.run(["sudo", "iwconfig", iface, "mode", "monitor"], check=True)
        # Arayüzü tekrar aktif et
        subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
        print(Fore.GREEN + "[+] Monitor mode enabled successfully.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Failed to enable monitor mode: {e}")
        print(Fore.YELLOW + "[!] Ensure you have the correct permissions (run as root) and a compatible Wi-Fi adapter.")
        wait_for_return()
        return

    # Wi-Fi ağlarını tara
    print(Fore.YELLOW + "[*] Scanning for Wi-Fi networks (10 seconds)...")
    wifi_networks = {}
    try:
        packets = scapy.sniff(iface=iface, timeout=10, filter="wlan type mgt subtype beacon")
        for packet in packets:
            if packet.haslayer(scapy.Dot11Beacon):
                ssid = packet[scapy.Dot11Elt].info.decode('utf-8', errors='ignore')
                if not ssid:  # Boş SSID'leri atla
                    continue
                bssid = packet[scapy.Dot11].addr2
                signal = packet.dBm_AntSignal if hasattr(packet, 'dBm_AntSignal') else "Unknown"
                # Şifreleme türünü belirle
                encryption = "Unknown"
                if packet.haslayer(scapy.Dot11Beacon):
                    if "WPA" in str(packet[scapy.Dot11Beacon].network_stats()):
                        encryption = "WPA/WPA2"
                    elif "WEP" in str(packet[scapy.Dot11Beacon].network_stats()):
                        encryption = "WEP"
                    else:
                        encryption = "Open"
                if ssid not in wifi_networks:
                    wifi_networks[ssid] = {
                        "SSID": ssid,
                        "BSSID": bssid,
                        "Signal": f"{signal} dBm" if signal != "Unknown" else "Unknown",
                        "Encryption": encryption,
                        "Channel": packet[scapy.Dot11Elt:3].info.decode('utf-8', errors='ignore') if packet[scapy.Dot11Elt:3].ID == 3 else "Unknown"
                    }
    except Exception as e:
        print(Fore.RED + f"[-] Error scanning Wi-Fi networks: {e}")
        print(Fore.YELLOW + "[!] Ensure your Wi-Fi adapter supports monitor mode and you have the correct permissions.")
        wait_for_return()
        return

    wifi_list = list(wifi_networks.values())
    if not wifi_list:
        print(Fore.RED + "[-] No Wi-Fi networks found.")
        wait_for_return()
        return

    # Wi-Fi ağlarını listele
    print(Fore.GREEN + "\n[+] Available Wi-Fi Networks:")
    for idx, wifi in enumerate(wifi_list, 1):
        print(Fore.CYAN + f"    {idx}. SSID: {wifi['SSID']}, BSSID: {wifi['BSSID']}, Signal: {wifi['Signal']}, Encryption: {wifi['Encryption']}, Channel: {wifi['Channel']}")

    # Kullanıcıdan bir ağ seçmesini iste
    try:
        choice = int(input(Fore.WHITE + "\nSelect a Wi-Fi network to crack (1-{}): ".format(len(wifi_list))))
        if choice < 1 or choice > len(wifi_list):
            print(Fore.RED + "[-] Invalid choice!")
            wait_for_return()
            return
    except ValueError:
        print(Fore.RED + "[-] Invalid input! Please enter a number.")
        wait_for_return()
        return

    selected_wifi = wifi_list[choice - 1]
    print(Fore.YELLOW + f"\n[*] Selected Wi-Fi: {selected_wifi['SSID']} (BSSID: {selected_wifi['BSSID']}, Channel: {selected_wifi['Channel']})")

    # Şifre kırma işlemi için handshake yakalama
    print(Fore.YELLOW + "[*] Capturing handshake for {}...".format(selected_wifi['SSID']))
    try:
        # Airodump-ng ile handshake yakalama
        print(Fore.CYAN + "[*] Starting airodump-ng to capture handshake (30 seconds)...")
        subprocess.run([
            "sudo", "airodump-ng", "--bssid", selected_wifi['BSSID'], "--channel", selected_wifi['Channel'],
            "--write", "handshake", iface
        ], timeout=30)
    except subprocess.TimeoutExpired:
        print(Fore.YELLOW + "[*] Handshake capture attempt finished.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Error capturing handshake: {e}")
        wait_for_return()
        return

    # Handshake dosyasını kontrol et
    handshake_file = "handshake-01.cap"
    import os
    if not os.path.exists(handshake_file):
        print(Fore.RED + "[-] Handshake could not be captured. Ensure there are active clients on the network.")
        wait_for_return()
        return

    # Şifre kırma işlemi
    wordlist = input(Fore.WHITE + "Please enter the path to your wordlist file (e.g., /path/to/rockyou.txt): ")
    if not os.path.exists(wordlist):
        print(Fore.RED + "[-] Wordlist file not found!")
        wait_for_return()
        return

    print(Fore.YELLOW + "[*] Starting password cracking with aircrack-ng...")
    try:
        result = subprocess.run([
            "sudo", "aircrack-ng", "-w", wordlist, "-b", selected_wifi['BSSID'], handshake_file
        ], capture_output=True, text=True, timeout=300)  # 5 dakika timeout
        output = result.stdout + result.stderr
        if "KEY FOUND" in output:
            password = re.search(r"KEY FOUND!\s*\[(.*?)\]", output)
            if password:
                print(Fore.GREEN + f"\n[+] Password Found: {password.group(1)}")
            else:
                print(Fore.RED + "[-] Password found but could not parse the key.")
        else:
            print(Fore.RED + "[-] Password not found in the wordlist.")
            print(Fore.YELLOW + "[!] Try a different wordlist or ensure the handshake was captured correctly.")
    except subprocess.TimeoutExpired:
        print(Fore.RED + "[-] Password cracking timed out after 5 minutes.")
    except subprocess.CalledProcessError as e:
        print(Fore.RED + f"[-] Error during password cracking: {e}")
    finally:
        # Monitor modunu kapat
        print(Fore.YELLOW + "[*] Disabling monitor mode on interface {}...".format(iface))
        try:
            subprocess.run(["sudo", "ifconfig", iface, "down"], check=True)
            subprocess.run(["sudo", "iwconfig", iface, "mode", "managed"], check=True)
            subprocess.run(["sudo", "ifconfig", iface, "up"], check=True)
            print(Fore.GREEN + "[+] Monitor mode disabled successfully.")
        except subprocess.CalledProcessError as e:
            print(Fore.RED + f"[-] Failed to disable monitor mode: {e}")

    wait_for_return()

# 7. Wi-Fi Admin Panel Access
def wifi_admin_panel_access():
    print(Fore.YELLOW + "[*] Starting Wi-Fi admin panel access...")
    modem_ip = input(Fore.WHITE + "Please enter the modem IP address (e.g., 192.168.1.1): ")
    if not modem_ip:
        print(Fore.RED + "[-] Modem IP not specified. Using default: 192.168.1.1.")
        modem_ip = "192.168.1.1"

    username = input(Fore.WHITE + "Please enter the Wi-Fi admin panel username: ")
    password = input(Fore.WHITE + "Please enter the Wi-Fi admin panel password: ")

    print(Fore.CYAN + f"Modem IP: {modem_ip}, Username: {username}, Password: {password}")
    try:
        response = requests.get(f"http://{modem_ip}", auth=(username, password), timeout=5)
        if response.status_code == 200:
            print(Fore.GREEN + "[+] Successfully accessed Wi-Fi admin panel!")
            print(Fore.YELLOW + "[*] Fetching admin panel data...")

            soup = BeautifulSoup(response.text, 'html.parser')

            modem_name = None
            for text in soup.stripped_strings:
                if "model" in text.lower() or "device name" in text.lower():
                    modem_name = text
                    break
            print(Fore.GREEN + f"[+] Modem Name: {modem_name if modem_name else 'Unknown'}")

            print(Fore.YELLOW + "[*] Looking for connected devices...")
            connected_devices = []
            for text in soup.stripped_strings:
                if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text):
                    connected_devices.append(text)
                elif re.match(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})', text):
                    connected_devices.append(text)
            if connected_devices:
                print(Fore.GREEN + "[+] Connected Devices:")
                for device in connected_devices:
                    print(Fore.CYAN + f"    - {device}")
            else:
                print(Fore.RED + "[-] No connected devices found.")

            print(Fore.YELLOW + "[*] Looking for logs...")
            logs = []
            for text in soup.stripped_strings:
                if "log" in text.lower() and (re.search(r'\d{4}-\d{2}-\d{2}', text) or "error" in text.lower()):
                    logs.append(text)
            if logs:
                print(Fore.GREEN + "[+] Logs:")
                for log in logs:
                    print(Fore.CYAN + f"    - {log}")
            else:
                print(Fore.RED + "[-] No logs found.")

            print(Fore.YELLOW + "[*] Looking for last login time...")
            last_login = None
            for text in soup.stripped_strings:
                if "last login" in text.lower() or re.search(r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}', text):
                    last_login = text
                    break
            print(Fore.GREEN + f"[+] Last Login Time: {last_login if last_login else 'Unknown'}")

            print(Fore.YELLOW + "[*] Extracting other data...")
            for text in soup.stripped_strings:
                if len(text) > 10:
                    print(Fore.CYAN + f"    - {text}")

        else:
            print(Fore.RED + f"[-] Access failed: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[-] Connection error: {e}")
    
    wait_for_return()

# 8. WHOIS Lookup
def whois_lookup():
    print(Fore.YELLOW + "[*] Starting WHOIS lookup...")
    target = input(Fore.WHITE + "Please enter the target IP or domain (e.g., 8.8.8.8 or example.com): ")
    
    try:
        whois = IPWhois(target)
        results = whois.lookup_rdap()
        print(Fore.GREEN + f"[+] WHOIS Information for {target}:")
        print(Fore.CYAN + f"    Network Name: {results.get('network', {}).get('name', 'Unknown')}")
        print(Fore.CYAN + f"    Organization: {results.get('network', {}).get('remarks', ['Unknown'])[0] if results.get('network', {}).get('remarks') else 'Unknown'}")
        print(Fore.CYAN + f"    Country: {results.get('network', {}).get('country', 'Unknown')}")
        print(Fore.CYAN + f"    CIDR: {results.get('network', {}).get('cidr', 'Unknown')}")
        print(Fore.CYAN + f"    Start Address: {results.get('network', {}).get('start_address', 'Unknown')}")
        print(Fore.CYAN + f"    End Address: {results.get('network', {}).get('end_address', 'Unknown')}")
    except Exception as e:
        print(Fore.RED + f"[-] Could not fetch WHOIS information: {e}")
    
    wait_for_return()

# 9. DNS Analysis
def dns_analysis():
    print(Fore.YELLOW + "[*] Starting DNS analysis...")
    domain = input(Fore.WHITE + "Please enter the target domain (e.g., example.com): ")

    try:
        print(Fore.YELLOW + "[*] Fetching DNS records...")
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                print(Fore.GREEN + f"[+] {record_type} Records:")
                for rdata in answers:
                    print(Fore.CYAN + f"    - {rdata}")
            except dns.resolver.NoAnswer:
                print(Fore.RED + f"[-] No {record_type} records found.")
            except Exception as e:
                print(Fore.RED + f"[-] Error fetching {record_type} records: {e}")
    except Exception as e:
        print(Fore.RED + f"[-] Could not perform DNS analysis: {e}")
    
    wait_for_return()

# 10. SSL/TLS Analysis
def ssl_analysis():
    print(Fore.YELLOW + "[*] Starting SSL/TLS analysis...")
    domain = input(Fore.WHITE + "Please enter the target domain (e.g., example.com): ")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(Fore.GREEN + f"[+] SSL Certificate Information for {domain}:")
                print(Fore.CYAN + f"    Issuer: {cert.get('issuer', 'Unknown')}")
                print(Fore.CYAN + f"    Subject: {cert.get('subject', 'Unknown')}")
                print(Fore.CYAN + f"    Valid From: {cert.get('notBefore', 'Unknown')}")
                print(Fore.CYAN + f"    Valid Until: {cert.get('notAfter', 'Unknown')}")
                print(Fore.CYAN + f"    Serial Number: {cert.get('serialNumber', 'Unknown')}")
    except Exception as e:
        print(Fore.RED + f"[-] Could not fetch SSL certificate: {e}")
    
    wait_for_return()

# 11. Network Device Detection
def network_device_detection(ip_range):
    print(Fore.YELLOW + "[*] Starting network device detection...")
    devices = []
    
    # Scapy ARP Scan
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)

    # Nmap Device Detection
    print(Fore.CYAN + "[*] Performing device detection with Nmap...")
    nm.scan(hosts=ip_range, arguments='-O --osscan-guess')
    
    for host in nm.all_hosts():
        if host in nm._scan_result.get('scan', {}):
            os_info = nm[host].get('osmatch', [])
            device_type = "Unknown"
            if os_info:
                device_type = os_info[0].get('name', 'Unknown')
            print(Fore.GREEN + f"[+] Device: IP: {host}, Type: {device_type}")
            for device in devices:
                if device['ip'] == host:
                    vendor = mac_db.get_manuf(device['mac']) or "Unknown"
                    print(Fore.CYAN + f"    MAC: {device['mac']}, Vendor: {vendor}")
    
    wait_for_return()

# 12. Network Speed Test
def network_speed_test():
    print(Fore.YELLOW + "[*] Starting network speed test...")
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download_speed = st.download() / 1_000_000  # Mbps
        upload_speed = st.upload() / 1_000_000  # Mbps
        ping = st.results.ping

        print(Fore.GREEN + f"[+] Download Speed: {download_speed:.2f} Mbps")
        print(Fore.GREEN + f"[+] Upload Speed: {upload_speed:.2f} Mbps")
        print(Fore.GREEN + f"[+] Ping: {ping:.2f} ms")
    except Exception as e:
        print(Fore.RED + f"[-] Could not perform speed test: {e}")
    
    wait_for_return()

# 13. Network Live Log Capture (Yeni Eklenen Bölüm)
def network_live_log_capture():
    print(Fore.YELLOW + "[*] Starting live network log capture...")
    print(Fore.RED + "[!] WARNING: This tool should only be used on networks you own or have explicit permission to monitor.")
    print(Fore.RED + "[!] Unauthorized network monitoring is illegal and can lead to serious legal consequences.")

    # Mevcut ağ arayüzlerini listele
    print(Fore.CYAN + "[*] Available network interfaces:")
    interfaces = scapy.get_if_list()
    for idx, iface in enumerate(interfaces, 1):
        print(Fore.CYAN + f"    {idx}. {iface}")

    # Kullanıcıdan arayüz seçmesini iste
    try:
        choice = int(input(Fore.WHITE + "\nSelect a network interface to monitor (1-{}): ".format(len(interfaces))))
        if choice < 1 or choice > len(interfaces):
            print(Fore.RED + "[-] Invalid choice!")
            wait_for_return()
            return
    except ValueError:
        print(Fore.RED + "[-] Invalid input! Please enter a number.")
        wait_for_return()
        return

    selected_iface = interfaces[choice - 1]
    print(Fore.YELLOW + f"\n[*] Selected interface: {selected_iface}")

    # Süreyi kullanıcıdan al (saniye cinsinden)
    try:
        duration = int(input(Fore.WHITE + "Enter the duration to capture logs (in seconds, e.g., 60): "))
        if duration <= 0:
            print(Fore.RED + "[-] Duration must be a positive number!")
            wait_for_return()
            return
    except ValueError:
        print(Fore.RED + "[-] Invalid input! Please enter a number.")
        wait_for_return()
        return

    print(Fore.YELLOW + f"[*] Capturing network logs for {duration} seconds... Press Ctrl+C to stop early.")

    # Logları saklamak için bir liste
    logs = []

    # Paket yakalama fonksiyonu
    def packet_handler(packet):
        log_entry = {}
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # IP katmanı varsa
        if packet.haslayer(scapy.IP):
            log_entry["Timestamp"] = timestamp
            log_entry["Source IP"] = packet[scapy.IP].src
            log_entry["Destination IP"] = packet[scapy.IP].dst
            log_entry["Protocol"] = packet[scapy.IP].proto

            # TCP veya UDP varsa port bilgilerini al
            if packet.haslayer(scapy.TCP):
                log_entry["Protocol Name"] = "TCP"
                log_entry["Source Port"] = packet[scapy.TCP].sport
                log_entry["Destination Port"] = packet[scapy.TCP].dport
            elif packet.haslayer(scapy.UDP):
                log_entry["Protocol Name"] = "UDP"
                log_entry["Source Port"] = packet[scapy.UDP].sport
                log_entry["Destination Port"] = packet[scapy.UDP].dport
            else:
                log_entry["Protocol Name"] = "Other"
                log_entry["Source Port"] = "N/A"
                log_entry["Destination Port"] = "N/A"

            # Logu ekrana yazdır
            print(Fore.GREEN + f"[+] {timestamp} | {log_entry['Source IP']}:{log_entry['Source Port']} -> "
                  f"{log_entry['Destination IP']}:{log_entry['Destination Port']} | "
                  f"Protocol: {log_entry['Protocol Name']} ({log_entry['Protocol']})")

            logs.append(log_entry)

    # Paket yakalamayı başlat
    try:
        scapy.sniff(iface=selected_iface, prn=packet_handler, timeout=duration)
    except Exception as e:
        print(Fore.RED + f"[-] Error capturing packets: {e}")
        print(Fore.YELLOW + "[!] Ensure you have the correct permissions (run as root on Linux) and Npcap installed (on Windows).")
        wait_for_return()
        return

    # Yakalanan logları özetle
    print(Fore.YELLOW + f"\n[*] Captured {len(logs)} packets.")
    if logs:
        print(Fore.GREEN + "[+] Summary of captured logs:")
        for log in logs:
            print(Fore.CYAN + f"    {log['Timestamp']} | {log['Source IP']}:{log['Source Port']} -> "
                  f"{log['Destination IP']}:{log['Destination Port']} | "
                  f"Protocol: {log['Protocol Name']} ({log['Protocol']})")
    else:
        print(Fore.RED + "[-] No packets captured during the specified duration.")

    wait_for_return()

# 14. Network Traffic Analysis
def network_traffic_analysis():
    print(Fore.YELLOW + "[*] Starting network traffic analysis...")
    print(Fore.CYAN + "[*] Capturing packets for 10 seconds... Press Ctrl+C to stop early.")

    try:
        packets = scapy.sniff(timeout=10)
        print(Fore.GREEN + f"[+] Captured {len(packets)} packets.")
        
        # Basit analiz
        protocols = {}
        for packet in packets:
            if packet.haslayer(scapy.IP):
                proto = packet[scapy.IP].proto
                protocols[proto] = protocols.get(proto, 0) + 1
        
        print(Fore.YELLOW + "[*] Protocol Distribution:")
        for proto, count in protocols.items():
            print(Fore.CYAN + f"    Protocol {proto}: {count} packets")
    except Exception as e:
        print(Fore.RED + f"[-] Could not capture packets: {e}")
    
    wait_for_return()

# 15. Network Interface Information
def network_interface_info():
    print(Fore.YELLOW + "[*] Starting network interface analysis...")
    try:
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            print(Fore.GREEN + f"[+] Interface: {iface}")
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    print(Fore.CYAN + f"    IP: {addr.get('addr', 'Unknown')}")
                    print(Fore.CYAN + f"    Netmask: {addr.get('netmask', 'Unknown')}")
            if netifaces.AF_LINK in addrs:
                for addr in addrs[netifaces.AF_LINK]:
                    print(Fore.CYAN + f"    MAC: {addr.get('addr', 'Unknown')}")
    except Exception as e:
        print(Fore.RED + f"[-] Could not fetch interface information: {e}")
    
    wait_for_return()

# Run all modules
def run_all_modules(ip_range, devices):
    network_scan(ip_range)
    modem_firmware_check()
    analyze_website()
    admin_panel_finder()
    ip_query()
    wifi_password_cracker()
    wifi_admin_panel_access()
    whois_lookup()
    dns_analysis()
    ssl_analysis()
    network_device_detection(ip_range)
    network_speed_test()
    network_live_log_capture()  # Yeni eklenen Network Live Log Capture modülü
    network_traffic_analysis()
    network_interface_info()

# Draw Zphisher-style banner
def draw_banner():
    banner = """
    ███████╗██╗    ██╗ ██████╗ ██████╗ ██╗   ██╗    ████████╗██████╗   ██████╗  ██╗
    ██╔════╝██║    ██║██╔═══██╗██╔══██╗╚██╗ ██╔╝    ╚══██╔══╝██╔══██╗ ██╔═══██╗ ██║
    ███████╗██║ █╗ ██║██║   ██║██████╔╝ ╚████╔╝        ██║   ███████╗ ██║   ██║ ██║
    ╚════██║██║███╗██║██║   ██║██╔═══╝   ╚██╔╝         ██║   ██╔══██╗ ██║   ██║ ██║
    ███████║╚███╔███╔╝╚██████╔╝██║        ██║          ██║   ██║  ██║ ╚██████╔╝ ██║
    ╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝        ╚═╝          ╚═╝   ╚═╝  ╚═╝  ╚═════╝  ╚═╝
    """
    print(Fore.CYAN + banner)
    print(Fore.GREEN + "Version: 1.0")
    print(Fore.CYAN + "[-] Tool Created by JosephSpace (SW)")
    print(Fore.GREEN + "[-] Copyright (C) 2025 SwopiTroi Developers")

# Main Menu (Zphisher-style, yatay sütunlar)
def main_menu():
    ip_range = input(Fore.WHITE + "Please enter the IP range to scan (e.g., 192.168.1.0/24): ")
    if not ip_range:
        print(Fore.RED + "[-] IP range not specified. Using default range (192.168.1.0/24).")
        ip_range = "192.168.1.0/24"

    # Initial scan for devices
    print(Fore.YELLOW + "[*] Performing initial scan...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices.append(device)

    while True:
        draw_banner()
        print(Fore.CYAN + "\n[-] Select An Option For Network Analysis [::]")
        print()

        # Zphisher-style menu with columns
        options = [
            ("01", "Network Scan"), ("06", "Website Panel Finder"), ("11", "Network Device Detection"),
            ("02", "Modem Firmware Check"), ("07", "Website Analyzer"), ("12", "Network Speed Test"),
            ("03", "Wi-Fi Admin Panel"), ("08", "Website Lookup"), ("13", "Network Live Log Capture"),
            ("04", "Wi-Fi Password"), ("09", "Website DNS "), ("14", "Network Traffic Analysis"),
            ("05", "Wi-Fi IP Location"), ("10", "Website SSL/TLS "), ("15", "Network Interface Info"),
            ("99", "Run All Modules"), ("50", "About"), ("00", "Exit")
        ]

        # Print options in columns (yatay sütunlar)
        for i in range(0, len(options), 3):
            row = options[i:i+3]
            line = ""
            for opt in row:
                line += f"{Fore.CYAN}[{opt[0]}] {Fore.GREEN}{opt[1]:<20} "
            print(line)

        choice = input(Fore.CYAN + "\n[-] Select an option: ")

        if choice == "00":
            print(Fore.RED + "[*] Exiting program...")
            print(Fore.GREEN + "Thank you! Developed by JosephSpace (SW).")
            print(Fore.CYAN + "See you! 😊")
            break
        elif choice == "50":
            print(Fore.CYAN + "\n[+] About SWOPY TROI")
            print(Fore.GREEN + "    Version: 1.1")
            print(Fore.GREEN + "    Authors: JosephSpace (SW)")
            print(Fore.GREEN + "    Description: A comprehensive network analysis tool.")
            wait_for_return()
        elif choice == "99":
            run_all_modules(ip_range, devices)
        else:
            if choice == "01":
                network_scan(ip_range)
            elif choice == "02":
                modem_firmware_check()
            elif choice == "03":
                wifi_admin_panel_access()
            elif choice == "04":
                wifi_password_cracker()
            elif choice == "05":
                ip_query()
            elif choice == "06":
                admin_panel_finder()
            elif choice == "07":
                analyze_website()
            elif choice == "08":
                whois_lookup()
            elif choice == "09":
                dns_analysis()
            elif choice == "10":
                ssl_analysis()
            elif choice == "11":
                network_device_detection(ip_range)
            elif choice == "12":
                network_speed_test()
            elif choice == "13":
                network_live_log_capture()  # Yeni eklenen Network Live Log Capture modülü
            elif choice == "14":
                network_traffic_analysis()
            elif choice == "15":
                network_interface_info()
            else:
                print(Fore.RED + f"[-] Invalid choice: {choice}")
                wait_for_return()

if __name__ == "__main__":
    main_menu()
