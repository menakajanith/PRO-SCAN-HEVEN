import requests
import socket
import ssl
import os
import json
import dns.resolver
import nmap
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from cryptography.fernet import Fernet
from rich.console import Console
from rich.table import Table
from rich.progress import track
from rich.prompt import Prompt, Confirm
from rich.panel import Panel
from rich.align import Align
import websocket  # For WebSocket scanning

console = Console()

# PRO SCAN HEVEN Tool Functions
def display_banner():
    banner_text = "[bold green]PRO SCAN HEVEN Tool[/bold green]"
    centered_banner = Align.center(banner_text)
    panel = Panel(centered_banner, border_style="bright_blue")
    console.print(panel)

def display_menu():
    panel = Panel.fit(
        "[bold blue]Options:[/bold blue]\n"
        "1. Check HTTP/HTTPS Response for a list of hosts\n"
        "2. Check IP Address for a list of hosts\n"
        "3. Check SSL/TLS Certificate Information\n"
        "4. Scan for Open Ports (TCP, UDP, WebSocket)\n"
        "5. Check Zero-Rated Websites\n"
        "6. Enumerate Subdomains\n"
        "7. Generate SNI Host Config File\n"
        "8. Test SNI Host\n"
        "9. Check DNS Leaks\n"
        "10. Check HTTP Headers\n"
        "11. Import Host Lists from URL\n"
        "12. Auto-Test SNI with Multiple Protocols\n"
        "13. Detect ISP-Specific Zero-Rated Patterns\n"
        "14. Parallel Host Scanning\n"
        "15. Generate Detailed Bug Report\n"
        "16. Password Encryptor Tool\n"
        "17. Exit",
        title="Menu",
        border_style="green"
    )
    console.print(panel)

def ensure_results_folder():
    os.makedirs("results", exist_ok=True)

def get_domain_ip(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        return f"Could not resolve IP: {e}"

def detect_cdn(headers, ip):
    cdn_providers = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "cf-connecting-ip"],
        "Akamai": ["akamai", "x-akamai-transformed", "x-akamai-request-id"],
        "Fastly": ["fastly", "x-fastly-request-id", "x-fastly-cache-status"],
        "Google CDN": ["x-goog-meta", "x-google-backend", "x-goog-origin"],
        "BunnyCDN": ["bunnycdn", "server: bunnycdn", "x-bunnycdn-cache-status"],
        "KeyCDN": ["x-keycdn-request-id", "x-keycdn-cache-status"],
        "Cloudfront": ["via", "x-cache", "x-amz-cf-id", "x-amz-cf-pop"],
        "CDN77": ["cdn77", "x-cdn77-request-id", "x-cdn77-cache-status"],
        "StackPath": ["x-stackpath", "stackpath", "x-stackpath-cdn"],
        "Incapsula": ["x-incapsula", "incapsula", "x-incapsula-sid"],
        "CacheFly": ["cachefly", "cf-cache-status", "x-cache"],
        "Microsoft Azure CDN": ["x-ms-cdn", "x-azure-request-id", "x-ms-origin"],
        "Cloudflare Stream": ["cf-stream", "cf-ray", "cf-cache-status"],
        "ChinaCache": ["chinacache", "x-cdn-origin", "x-chinacache-request-id"],
        "Rackspace CDN": ["rackcdn", "x-rackcdn-cache-status"],
        "MaxCDN": ["maxcdn", "x-maxcdn-request-id", "x-maxcdn-cache-status"],
        "CDN Planet": ["cdnplanet", "x-cdn-planet-id"],
        "Imperva": ["x-imperva", "imperva", "x-imperva-cookie"],
        "Level3": ["level3", "x-level3-cache-status"],
        "Tencent Cloud CDN": ["tencentcloud", "x-tencent-cdn"],
        "Varnish": ["via", "x-varnish", "x-varnish-request-id"],
        "CDNify": ["cdnify", "x-cdnify-request-id"],
        "ArvanCloud": ["x-arv-cdn-request-id", "arvancloud", "x-arvancloud-cache-status"],
        "Sucuri": ["sucuri", "x-sucuri-cache"],
        "Limelight Networks": ["limelight", "x-limelight-cache-status"],
        "EdgeCast": ["edgecast", "x-edgecast-cache-status"],
        "NetDNA": ["netdna", "x-netdna-cache-status"],
        "F5": ["f5", "x-f5-cache-status"],
        "QCDN": ["qcdn", "x-qcdn-cache-status"],
        "Cloudflare Workers": ["cf-worker", "cf-ray", "cf-cache-status"],
        "Alibaba Cloud CDN": ["aliyuncdn", "x-aliyun-cdn-cache-status"],
        "Tata Communications CDN": ["tatacommunications", "x-tatacommunications-cache-status"],
    }
    for cdn, identifiers in cdn_providers.items():
        for key in identifiers:
            if key.lower() in [h.lower() for h in headers.keys()]:
                return cdn
    return "Unknown"

def check_http_response(url):
    results = {}
    protocols = ["http://", "https://"]
    for protocol in protocols:
        full_url = protocol + url if not url.startswith(('http://', 'https://')) else url
        try:
            response = requests.get(full_url, timeout=5)
            ip = get_domain_ip(full_url)
            cdn = detect_cdn(response.headers, ip)
            results[protocol] = {
                "status_code": response.status_code,
                "url": full_url,
                "headers": dict(response.headers),
                "cdn": cdn,
                "ip": ip
            }
        except requests.exceptions.RequestException as e:
            results[protocol] = {
                "url": full_url,
                "error": str(e),
                "cdn": "Unknown",
                "ip": get_domain_ip(full_url)
            }
    return results

def check_ssl_cert(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "subject": dict(x[0] for x in cert['subject']),
                    "notBefore": cert['notBefore'],
                    "notAfter": cert['notAfter'],
                    "serialNumber": cert['serialNumber']
                }
    except Exception as e:
        return {"error": f"Could not check SSL/TLS: {str(e)}"}

def scan_tcp_ports(domain, port_range="1-100"):
    try:
        nm = nmap.PortScanner()
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        nm.scan(domain, arguments=f"-p {port_range} -sV -O")  # Service version + OS detection
        result = f"TCP Scan Results for {domain}:\n"
        for host in nm.all_hosts():
            result += f"Host: {host} ({nm[host].hostname()})\n"
            if 'osclass' in nm[host]:
                os_info = nm[host]['osclass']
                result += f"OS: {os_info.get('osfamily', 'Unknown')} ({os_info.get('osgen', 'Unknown')})\n"
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    version = nm[host][proto][port].get('product', '') + ' ' + nm[host][proto][port].get('version', '')
                    result += f"Port {port}/{proto}: {state} ({service} {version.strip()})\n"
        return result
    except Exception as e:
        return f"Error scanning TCP ports: {str(e)}"

def scan_udp_ports(domain, port_range="53,123,161,500"):
    try:
        nm = nmap.PortScanner()
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        nm.scan(domain, arguments=f"-p {port_range} -sU")  # UDP scan
        result = f"UDP Scan Results for {domain}:\n"
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    result += f"Port {port}/{proto}: {state} ({service})\n"
        return result if "Port" in result else f"No open UDP ports found for {domain}\n"
    except Exception as e:
        return f"Error scanning UDP ports: {str(e)}"

def scan_websocket(domain, ports="80,443"):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        result = f"WebSocket Scan Results for {domain}:\n"
        protocols = ["ws", "wss"]
        port_list = [int(p) for p in ports.split(",")]
        for port in port_list:
            for proto in protocols:
                ws_url = f"{proto}://{domain}:{port}"
                try:
                    ws = websocket.WebSocket()
                    ws.connect(ws_url, timeout=5)
                    ws.close()
                    result += f"WebSocket {ws_url}: Open\n"
                except Exception as e:
                    result += f"WebSocket {ws_url}: Closed ({str(e)})\n"
        return result
    except Exception as e:
        return f"Error scanning WebSocket: {str(e)}"

def scan_ports_from_file(file_path):
    ensure_results_folder()
    output_file = "results/port_scan.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    tcp_port_range = Prompt.ask("Enter TCP port range (e.g., 1-100, default is 1-100)", default="1-100")
    udp_port_range = Prompt.ask("Enter UDP port range (e.g., 53,123,161,500, default is 53,123,161,500)", default="53,123,161,500")
    ws_ports = Prompt.ask("Enter WebSocket ports (e.g., 80,443, default is 80,443)", default="80,443")
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Scanning ports..."):
            if not host.strip():
                continue
            # TCP Scan
            tcp_result = scan_tcp_ports(host, tcp_port_range)
            console.print(tcp_result)
            outfile.write(tcp_result + "-" * 40 + "\n")
            # UDP Scan
            udp_result = scan_udp_ports(host, udp_port_range)
            console.print(udp_result)
            outfile.write(udp_result + "-" * 40 + "\n")
            # WebSocket Scan
            ws_result = scan_websocket(host, ws_ports)
            console.print(ws_result)
            outfile.write(ws_result + "-" * 40 + "\n")
            outfile.flush()

def check_zero_rated(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        response = requests.get(f"https://{domain}", timeout=5, allow_redirects=True)
        if response.status_code == 200:
            return f"{domain}: Likely zero-rated (Status: 200 OK)"
        else:
            return f"{domain}: Not zero-rated (Status: {response.status_code})"
    except requests.exceptions.RequestException as e:
        return f"{domain}: Error checking zero-rated status: {str(e)}"

def enumerate_subdomains(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        common_subdomains = ['www', 'api', 'm', 'mobile', 'mbasic', 'app']
        results = []
        for sub in common_subdomains:
            try:
                full_domain = f"{sub}.{domain}"
                answers = dns.resolver.resolve(full_domain, 'A')
                for rdata in answers:
                    results.append(f"{full_domain}: {rdata.address}")
            except:
                continue
        return results if results else [f"No subdomains found for {domain}"]
    except Exception as e:
        return [f"Error enumerating subdomains: {str(e)}"]

def generate_config(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        config = {
            "sni": domain,
            "port": 443,
            "protocol": "SSL/TLS",
            "app": "HTTP Injector",
            "note": f"Generated config for {domain}"
        }
        os.makedirs("configs", exist_ok=True)
        with open(f"configs/{domain}_config.json", "w") as f:
            json.dump(config, f, indent=4)
        return f"Config file generated: configs/{domain}_config.json"
    except Exception as e:
        return f"Error generating config: {str(e)}"

def test_sni_host(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        response = requests.get(f"https://{domain}", timeout=5, headers={"Host": domain})
        if response.status_code == 200:
            return f"{domain}: SNI host likely working (Status: 200 OK)"
        else:
            return f"{domain}: SNI host not working (Status: {response.status_code})"
    except Exception as e:
        return f"{domain}: Error testing SNI host: {str(e)}"

def check_dns_leak(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        answers = dns.resolver.resolve(domain, 'A')
        dns_servers = dns.resolver.Resolver().nameservers
        results = [f"{domain}: Resolved IP: {rdata.address}" for rdata in answers]
        results.append(f"DNS Servers: {dns_servers}")
        return "\n".join(results)
    except Exception as e:
        return f"{domain}: Error checking DNS: {str(e)}"

def check_http_headers(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        response = requests.get(f"https://{domain}", timeout=5)
        headers = dict(response.headers)
        result = f"HTTP Headers for {domain}:\n"
        for key, value in headers.items():
            result += f"{key}: {value}\n"
        return result
    except Exception as e:
        return f"{domain}: Error checking headers: {str(e)}"

def check_headers_from_file(file_path):
    ensure_results_folder()
    output_file = "results/http_headers.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Checking HTTP headers..."):
            if not host.strip():
                continue
            result = check_http_headers(host)
            console.print(result)
            outfile.write(result + "-" * 40 + "\n")
            outfile.flush()

def import_host_list(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        hosts = [a.text for a in soup.find_all('a') if '.' in a.text]
        ensure_results_folder()
        with open("results/imported_hosts.txt", 'w') as f:
            f.write('\n'.join(hosts))
        return f"Imported {len(hosts)} hosts to results/imported_hosts.txt"
    except Exception as e:
        return f"Error importing hosts: {str(e)}"

def auto_test_sni_protocols(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        protocols = ["SSL/TLS", "HTTP"]
        results = []
        for proto in protocols:
            if proto == "SSL/TLS":
                response = requests.get(f"https://{domain}", timeout=5, headers={"Host": domain})
                status = "Working" if response.status_code == 200 else "Not Working"
            else:  # HTTP
                response = requests.get(f"http://{domain}", timeout=5)
                status = "Working" if response.status_code == 200 else "Not Working"
            results.append(f"{domain} with {proto}: {status} (Status: {response.status_code})")
        return "\n".join(results)
    except Exception as e:
        return f"{domain}: Error testing protocols: {str(e)}"

def detect_isp_patterns(domain):
    try:
        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
        response = requests.get(f"https://{domain}", timeout=5)
        headers = dict(response.headers)
        patterns = {
            "Zero-Rated": "Allow" in headers or response.status_code == 200,
            "Port": 443 if "https" in response.url else 80,
            "SNI": domain
        }
        result = f"ISP Patterns for {domain}:\n"
        for key, value in patterns.items():
            result += f"{key}: {value}\n"
        return result
    except Exception as e:
        return f"{domain}: Error detecting ISP patterns: {str(e)}"

def parallel_scan_hosts(file_path, check_function):
    ensure_results_folder()
    output_file = f"results/parallel_{check_function.__name__}.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = [h.strip() for h in file.read().splitlines() if h.strip()]
    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(check_function, hosts))
    with open(output_file, "w") as outfile:
        for result in results:
            console.print(result)
            outfile.write(str(result) + "\n" + "-" * 40 + "\n")
            outfile.flush()

def generate_bug_report(hosts, results):
    ensure_results_folder()
    output_file = "results/bug_report.pdf"
    c = canvas.Canvas(output_file, pagesize=letter)
    c.drawString(50, 750, "PRO SCAN HEVEN Bug Hunting Report")
    y = 700
    for host, result in zip(hosts, results):
        c.drawString(50, y, f"Host: {host}")
        c.drawString(50, y-15, f"Result: {result[:50]}...")
        y -= 30
        if y < 50:
            c.showPage()
            y = 750
    c.save()
    return f"Bug report generated: {output_file}"

def check_response_from_file(file_path):
    ensure_results_folder()
    output_file = "results/response.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Processing hosts..."):
            if not host.strip():
                continue
            response = check_http_response(host)
            for protocol, data in response.items():
                output = f"Results for {data['url']}:\n"
                output += f"IP: {data['ip']}\n"
                if "error" in data:
                    output += f"Status: Error\n"
                    output += f"Error: {data['error']}\n"
                else:
                    output += f"Status Code: {data['status_code']}\n"
                    output += f"Status: OK\n"
                output += f"CDN: {data['cdn']}\n"
                output += "-" * 40 + "\n"
                console.print(output)
                outfile.write(output)
                outfile.flush()

def check_ip_from_file(file_path):
    ensure_results_folder()
    output_file = "results/ip_response.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Resolving IPs..."):
            if not host.strip():
                continue
            ip = get_domain_ip(host)
            output = f"IP for {host}: {ip}\n" + "-" * 40 + "\n"
            console.print(output)
            outfile.write(output)
            outfile.flush()

def check_ssl_from_file(file_path):
    ensure_results_folder()
    output_file = "results/ssl_response.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Checking SSL/TLS..."):
            if not host.strip():
                continue
            cert_info = check_ssl_cert(host)
            output = f"SSL/TLS Certificate for {host}:\n"
            if "error" in cert_info:
                output += f"Error: {cert_info['error']}\n"
            else:
                output += f"Issuer: {cert_info['issuer'].get('organizationName', 'Unknown')}\n"
                output += f"Subject: {cert_info['subject'].get('commonName', 'Unknown')}\n"
                output += f"Valid From: {cert_info['notBefore']}\n"
                output += f"Valid Until: {cert_info['notAfter']}\n"
                output += f"Serial Number: {cert_info['serialNumber']}\n"
            output += "-" * 40 + "\n"
            console.print(output)
            outfile.write(output)
            outfile.flush()

def check_zero_rated_from_file(file_path):
    ensure_results_folder()
    output_file = "results/zero_rated.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Checking zero-rated..."):
            if not host.strip():
                continue
            result = check_zero_rated(host)
            console.print(result)
            outfile.write(result + "\n" + "-" * 40 + "\n")
            outfile.flush()

def enumerate_subdomains_from_file(file_path):
    ensure_results_folder()
    output_file = "results/subdomains.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Enumerating subdomains..."):
            if not host.strip():
                continue
            results = enumerate_subdomains(host)
            output = f"Subdomains for {host}:\n" + "\n".join(results) + "\n"
            console.print(output)
            outfile.write(output + "-" * 40 + "\n")
            outfile.flush()

def test_sni_from_file(file_path):
    ensure_results_folder()
    output_file = "results/sni_test.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Testing SNI hosts..."):
            if not host.strip():
                continue
            result = test_sni_host(host)
            console.print(result)
            outfile.write(result + "\n" + "-" * 40 + "\n")
            outfile.flush()

def check_dns_leak_from_file(file_path):
    ensure_results_folder()
    output_file = "results/dns_leak.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Checking DNS leaks..."):
            if not host.strip():
                continue
            result = check_dns_leak(host)
            console.print(result)
            outfile.write(result + "\n" + "-" * 40 + "\n")
            outfile.flush()

def auto_test_protocols_from_file(file_path):
    ensure_results_folder()
    output_file = "results/sni_protocol_test.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Testing SNI protocols..."):
            if not host.strip():
                continue
            result = auto_test_sni_protocols(host)
            console.print(result)
            outfile.write(result + "\n" + "-" * 40 + "\n")
            outfile.flush()

def detect_isp_patterns_from_file(file_path):
    ensure_results_folder()
    output_file = "results/isp_patterns.txt"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    with open(output_file, "w") as outfile:
        for host in track(hosts, description="Detecting ISP patterns..."):
            if not host.strip():
                continue
            result = detect_isp_patterns(host)
            console.print(result)
            outfile.write(result + "\n" + "-" * 40 + "\n")
            outfile.flush()

def generate_bug_report_from_file(file_path):
    ensure_results_folder()
    output_file = "results/bug_report.pdf"
    if not os.path.exists(file_path):
        error_message = f"Error: File '{file_path}' not found.\n"
        console.print(f"[red]{error_message}[/red]")
        with open(output_file, "w") as outfile:
            outfile.write(error_message)
        return
    with open(file_path, 'r') as file:
        hosts = file.read().splitlines()
    results = []
    for host in track(hosts, description="Generating bug report..."):
        if not host.strip():
            continue
        result = f"Host: {host}\n"
        result += check_zero_rated(host) + "\n"
        result += test_sni_host(host) + "\n"
        results.append(result)
    console.print(generate_bug_report(hosts, results))

# Password Encryptor Tool Functions
def display_encryptor_banner():
    banner_text = "[bold green]Password Encryptor Tool[/bold green]"
    centered_banner = Align.center(banner_text)
    panel = Panel(centered_banner, border_style="bright_blue")
    console.print(panel)

def display_encryptor_menu():
    panel = Panel.fit(
        "[bold blue]Options:[/bold blue]\n"
        "1. Generate and Save Encryption Key\n"
        "2. Encrypt Passwords (Auto Delete Original)\n"
        "3. Decrypt Passwords\n"
        "4. Back",
        title="Menu",
        border_style="green"
    )
    console.print(panel)

def ensure_secure_data_folder():
    os.makedirs("secure_data/keys", exist_ok=True)
    os.makedirs("secure_data/encrypted", exist_ok=True)
    os.makedirs("secure_data/decrypted", exist_ok=True)

def generate_key():
    key = Fernet.generate_key()
    ensure_secure_data_folder()
    key_file = "secure_data/keys/encryption_key.key"
    with open(key_file, "wb") as f:
        f.write(key)
    console.print(f"[green]Key generated and saved to {key_file}[/green]")
    if Confirm.ask("Do you want to back up the encryption key?"):
        with open("secure_data/keys/backup_key.key", "wb") as f:
            f.write(key)
        console.print("[green]Key backed up to secure_data/keys/backup_key.key[/green]")
    return key

def load_key():
    key_file = "secure_data/keys/encryption_key.key"
    if not os.path.exists(key_file):
        console.print("[red]Key file not found! Generate a key first.[/red]")
        return None
    with open(key_file, "rb") as f:
        return f.read()

def encrypt_password(password, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(password.encode())
    return encrypted

def decrypt_password(encrypted, key):
    try:
        fernet = Fernet(key)
        decrypted = fernet.decrypt(encrypted).decode()
        return decrypted
    except Exception as e:
        return f"Error decrypting: {str(e)}"

def encrypt_passwords_file(passwords_file, encrypted_file):
    key = load_key()
    if not key:
        return
    if not os.path.exists(passwords_file):
        console.print(f"[red]Password file '{passwords_file}' not found![/red]")
        return
    ensure_secure_data_folder()
    with open(passwords_file, "r") as f:
        passwords = f.read().splitlines()
    with open(encrypted_file, "wb") as f:
        for password in passwords:
            if password.strip():
                encrypted = encrypt_password(password, key)
                f.write(encrypted + b"\n")
    console.print(f"[green]Passwords encrypted and saved to {encrypted_file}[/green]")
    delete_confirm = Confirm.ask(f"Do you want to delete the original file '{passwords_file}' for safety?")
    if delete_confirm:
        try:
            os.remove(passwords_file)
            console.print(f"[green]Original file '{passwords_file}' deleted successfully.[/green]")
        except Exception as e:
            console.print(f"[red]Error deleting original file: {str(e)}[/red]")
    else:
        console.print(f"[yellow]Original file '{passwords_file}' was not deleted.[/yellow]")

def decrypt_passwords_file(encrypted_file):
    key = load_key()
    if not key:
        return
    if not os.path.exists(encrypted_file):
        console.print(f"[red]Encrypted file '{encrypted_file}' not found![/red]")
        return
    with open(encrypted_file, "rb") as f:
        encrypted_lines = f.read().splitlines()
    decrypted_passwords = []
    console.print("[yellow]Decrypted Passwords:[/yellow]")
    for encrypted in encrypted_lines:
        decrypted = decrypt_password(encrypted, key)
        console.print(f"[cyan]{decrypted}[/cyan]")
        decrypted_passwords.append(decrypted)
    
    save_confirm = Confirm.ask("Do you want to save the decrypted passwords to a file?")
    if save_confirm:
        decrypted_file = "secure_data/decrypted/decrypted_passwords.txt"
        ensure_secure_data_folder()
        if os.path.exists(decrypted_file):
            overwrite_confirm = Confirm.ask(f"File '{decrypted_file}' already exists. Overwrite?")
            if not overwrite_confirm:
                console.print(f"[yellow]Decrypted passwords not saved.[/yellow]")
                return
        try:
            with open(decrypted_file, "w") as f:
                f.write("\n".join(decrypted_passwords) + "\n")
            console.print(f"[green]Decrypted passwords saved to {decrypted_file}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving decrypted passwords: {str(e)}[/red]")

def password_encryptor_main():
    while True:
        console.clear()
        display_encryptor_banner()
        display_encryptor_menu()
        choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4"], default="1")
        if choice == '1':
            generate_key()
        elif choice == '2':
            passwords_file = Prompt.ask("Enter the path to the passwords file (e.g., passwords.txt)")
            encrypted_file = "secure_data/encrypted/encrypted_passwords.txt"
            encrypt_passwords_file(passwords_file, encrypted_file)
        elif choice == '3':
            encrypted_file = Prompt.ask("Enter the path to the encrypted file (e.g., secure_data/encrypted/encrypted_passwords.txt)", default="secure_data/encrypted/encrypted_passwords.txt")
            decrypt_passwords_file(encrypted_file)
        elif choice == '4':
            return
        Prompt.ask("\nPress Enter to continue...")

# Main Function
def main():
    while True:
        console.clear()
        display_banner()
        display_menu()
        choice = Prompt.ask("Enter your choice", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17"], default="1")
        if choice == '17':
            console.print("[green]Thank you for using PRO SCAN HEVEN Tool. Exiting...[/green]")
            break
        if choice == '16':
            password_encryptor_main()
            continue
        if choice in ['1', '2', '3', '4', '5', '6', '8', '9', '10', '12', '13', '15']:
            file_path = Prompt.ask("Enter the path to the text file (e.g., hosts.txt)")
            if choice == '1':
                check_response_from_file(file_path)
            elif choice == '2':
                check_ip_from_file(file_path)
            elif choice == '3':
                check_ssl_from_file(file_path)
            elif choice == '4':
                scan_ports_from_file(file_path)
            elif choice == '5':
                check_zero_rated_from_file(file_path)
            elif choice == '6':
                enumerate_subdomains_from_file(file_path)
            elif choice == '8':
                test_sni_from_file(file_path)
            elif choice == '9':
                check_dns_leak_from_file(file_path)
            elif choice == '10':
                check_headers_from_file(file_path)
            elif choice == '12':
                auto_test_protocols_from_file(file_path)
            elif choice == '13':
                detect_isp_patterns_from_file(file_path)
            elif choice == '15':
                generate_bug_report_from_file(file_path)
        elif choice == '7':
            domain = Prompt.ask("Enter the SNI host domain to generate config for")
            console.print(generate_config(domain))
        elif choice == '11':
            url = Prompt.ask("Enter the URL to import host list from")
            console.print(import_host_list(url))
        elif choice == '14':
            file_path = Prompt.ask("Enter the path to the text file (e.g., hosts.txt)")
            scan_type = Prompt.ask("Enter scan type (http, ip, ssl, ports, zero, subdomains, sni, dns, headers)", 
                                  choices=["http", "ip", "ssl", "ports", "zero", "subdomains", "sni", "dns", "headers"])
            scan_functions = {
                "http": lambda x: str(check_http_response(x)),
                "ip": get_domain_ip,
                "ssl": lambda x: str(check_ssl_cert(x)),
                "ports": lambda x: scan_tcp_ports(x, "1-100") + "\n" + scan_udp_ports(x, "53,123,161,500") + "\n" + scan_websocket(x, "80,443"),
                "zero": check_zero_rated,
                "subdomains": lambda x: "\n".join(enumerate_subdomains(x)),
                "sni": test_sni_host,
                "dns": check_dns_leak,
                "headers": check_http_headers
            }
            parallel_scan_hosts(file_path, scan_functions[scan_type])
        Prompt.ask("\nPress Enter to continue...")

if __name__ == "__main__":
    main()
