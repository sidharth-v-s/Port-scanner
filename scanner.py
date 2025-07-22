import socket
import argparse
import subprocess
import platform
import struct

# Dictionary of well-known ports and their default services
KNOWN_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    135: "MS RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram Service",
    139: "NetBIOS Session Service",
    143: "IMAP",
    389: "LDAP",
    445: "SMB",
    464: "Kerberos Change/Set Password",
    636: "LDAPS",
    3268: "Global Catalog",
    3269: "Global Catalog SSL",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    593: "RPC over HTTP",
    993: "IMAPS",
    995: "POP3S",
    1723: "PPTP",
    3306: "MySQL",
    5432: "PostgreSQL",
    5900: "VNC",
    8000: "HTTP",
    8080: "HTTP"
}

# Simple Port Scanner

def is_host_up(target):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, "1", target]
    try:
        result = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def detect_os(target):
    # Use ping and parse TTL for basic OS guess
    try:
        if platform.system().lower() == "windows":
            command = ["ping", "-n", "1", target]
        else:
            command = ["ping", "-c", "1", target]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = proc.communicate()
        out = out.decode(errors="ignore")
        ttl = None
        for line in out.splitlines():
            if "ttl=" in line.lower():
                # Try to extract TTL value
                parts = line.lower().split("ttl=")
                if len(parts) > 1:
                    ttl_str = ''
                    for c in parts[1]:
                        if c.isdigit():
                            ttl_str += c
                        else:
                            break
                    if ttl_str:
                        ttl = int(ttl_str)
                        break
        if ttl is not None:
            if ttl <= 64:
                os_guess = "Linux/Unix"
            elif ttl <= 128:
                os_guess = "Windows"
            else:
                os_guess = "Unknown/Other"
            print(f"[OS Detection] TTL={ttl} -> Likely OS: {os_guess}")
        else:
            print("[OS Detection] Could not determine TTL from ping reply.")
    except Exception as e:
        print(f"[OS Detection] Error: {e}")

def grab_banner(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((target, port))

        # Many services (FTP, SSH) send a banner immediately. Try a non-blocking read.
        banner_bytes = b""
        try:
            s.setblocking(False)
            banner_bytes = s.recv(1024)
        except (BlockingIOError, socket.error):
            # Expected for passive services (e.g., HTTP).
            pass
        finally:
            s.setblocking(True)

        # If no initial banner, probe for HTTP.
        if not banner_bytes:
            try:
                s.sendall(b'HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n')
                banner_bytes = s.recv(1024)
            except socket.error:
                # If that fails, it's not a talkative or HTTP service we can easily probe.
                pass
        
        s.close()

        if banner_bytes:
            banner = banner_bytes.decode(errors='ignore').strip()
            # Return the full banner for detailed parsing
            return banner
        
        return None
    except Exception:
        return None

def scan_ports(target, ports, version_detect=False):
    results = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            result = s.connect_ex((target, port))
            if result == 0:
                service = ""
                if version_detect:
                    banner = grab_banner(target, port)
                    if banner:
                        banner_lines = banner.splitlines()
                        first_line = banner_lines[0] if banner_lines else banner
                        banner_lower = banner.lower()

                        if 'http' in banner_lower:
                            http_server = None
                            for line in banner_lines:
                                if line.lower().startswith("server:"):
                                    http_server = line.split(":", 1)[1].strip()
                                    break
                            if http_server:
                                service = f"HTTP ({http_server})"
                            else:
                                service = "HTTP"
                        elif banner.startswith("SSH-"):
                            service = first_line
                        elif "ftp" in banner_lower:
                            service = first_line
                        elif "smtp" in banner_lower:
                            service = first_line
                        else:
                            service = first_line
                    else:
                        service = KNOWN_SERVICES.get(port, "Unknown")
                else:
                    service = KNOWN_SERVICES.get(port, "")
                results.append((port, "OPEN", service))
            s.close()
        except Exception as e:
            results.append((port, "ERROR", str(e)))
    if version_detect:
        print(f"{'PORT':<8}{'STATE':<10}{'SERVICE':<40}")
        print("-"*58)
    else:
        print(f"{'PORT':<8}{'STATE':<10}")
        print("-"*18)
    for row in results:
        if version_detect:
            print(f"{row[0]:<8}{row[1]:<10}{row[2]:<40}")
        else:
            print(f"{row[0]:<8}{row[1]:<10}")
    open_ports = [r[0] for r in results if r[1] == "OPEN"]
    if not open_ports:
        print("\nNo open ports found in the specified ports.")
    else:
        print(f"\nOpen ports: {open_ports}")

def parse_ports(port_str):
    ports = set()
    for part in port_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner")
    parser.add_argument("target", help="Target host (IP or domain)")
    parser.add_argument("--start", type=int, help="Start port (for range scan)")
    parser.add_argument("--end", type=int, help="End port (for range scan)")
    parser.add_argument("-p", "--ports", help="Comma-separated list of ports or ranges to scan, e.g. 22,80,1000-1005")
    parser.add_argument("-Pn", "--no-ping", action="store_true", help="Skip host discovery (ping probe), scan even if host seems down")
    parser.add_argument("-v", "--version-detect", action="store_true", help="Attempt to detect service version (banner grab)")
    parser.add_argument("-O", "--os-detect", action="store_true", help="Attempt to detect remote OS (basic, TTL-based)")
    args = parser.parse_args()

    if args.os_detect:
        detect_os(args.target)

    if not args.no_ping:
        print(f"Pinging {args.target} to check if host is up...")
        if not is_host_up(args.target):
            print(f"Host {args.target} appears to be down. Use -Pn to skip ping check.")
            return
        else:
            print(f"Host {args.target} is up. Proceeding with scan.")
    else:
        print("Skipping ping probe (-Pn specified). Proceeding with scan.")

    if args.ports:
        ports = parse_ports(args.ports)
    elif args.start is not None and args.end is not None:
        ports = list(range(args.start, args.end + 1))
    else:
        print("You must specify either -p/--ports or both --start and --end.")
        return
    scan_ports(args.target, ports, version_detect=args.version_detect)

if __name__ == "__main__":
    main()
