# Port-scanner

A fast, flexible, and user-friendly port scanner written in Python. Supports service and version detection, OS guessing, and is suitable for scanning both Linux and Windows/Active Directory environments.

## Features
- Scan a range of ports or specific ports on a target host
- Service detection for well-known protocols (HTTP, FTP, SSH, SMB, LDAP, RDP, etc.)
- Version detection (banner grabbing) for HTTP, FTP, SSH, and more
- OS detection using ping TTL heuristics
- Clean, table-formatted output
- No external dependencies (pure Python)

## Usage

```bash
python3 scanner.py <target> [options]
```

### Options
- `--start <port>`: Start of port range (inclusive)
- `--end <port>`: End of port range (inclusive)
- `-p, --ports <list>`: Comma-separated list of ports or ranges (e.g. `22,80,443,1000-1005`)
- `-v, --version-detect`: Enable service version detection (banner grabbing)
- `-O, --os-detect`: Attempt to detect remote OS (basic, TTL-based)
- `-Pn, --no-ping`: Skip host discovery (ping probe), scan even if host seems down

### Examples

Scan a range of ports:
```bash
python3 scanner.py 192.168.1.7 --start 1 --end 10000
```

Scan specific ports:
```bash
python3 scanner.py 192.168.1.7 -p 22,80,443,3389
```

Scan with service version detection and OS detection:
```bash
python3 scanner.py 192.168.1.7 --start 1 --end 10000 -v -O
```

Skip ping check (scan even if host seems down):
```bash
python3 scanner.py 192.168.1.7 -p 445,3389 -Pn
```

## Supported Protocols/Ports
- HTTP, HTTPS, FTP, SSH, Telnet, SMTP, DNS, POP3, IMAP, SMB, NetBIOS, LDAP, LDAPS, Kerberos, RDP, WinRM, MySQL, PostgreSQL, VNC, and more
- See the source for the full list of recognized ports

## Output Example
```
PORT    STATE     SERVICE                                 
----------------------------------------------------------
22      OPEN      SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3 
80      OPEN      HTTP (Apache/2.4.52 (Ubuntu))           
445     OPEN      SMB                                      
3389    OPEN      RDP                                      
```

## Repository
[github.com/sidharth-v-s/Port-scanner](https://github.com/sidharth-v-s/Port-scanner)

---

**For educational and authorized testing purposes only.** 