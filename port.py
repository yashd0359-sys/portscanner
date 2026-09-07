import concurrent.futures
import socket
import sys
import time

def get_service_name(port):
    """Resolve well-known service names for common ports."""
    try:
        return socket.getservbyport(port, "tcp")
    except (OSError, socket.error):
        return "Unknown"

def grab_banner(target_ip, port, timeout=1.0):
    """Attempt to retrieve the service banner/version if available."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            # Send a generic newline to trigger a banner on services like HTTP/FTP/SMTP
            s.send(b"\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            # Return first line of banner, truncated for readability
            return banner.splitlines()[0][:40] if banner else "No banner"
    except Exception:
        return "No banner"

def check_port(target_ip, port, timeout=0.5):
    """Scan a single port and collect service metadata if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                service = get_service_name(port)
                banner = grab_banner(target_ip, port)
                return {
                    "port": port,
                    "service": service,
                    "banner": banner,
                    "status": "OPEN",
                }
    except Exception:
        pass
    return None

def scan_ports(target, start_port, end_port, max_workers=50):
    print(f"\nResolving target: {target}...")
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Error: Hostname could not be resolved.")
        return

    total_ports = end_port - start_port + 1
    print(f"Target IP: {target_ip}")
    print(f"Scanning {total_ports} ports with {max_workers} worker threads...")
    print("=" * 65)

    start_time = time.time()
    open_ports = []

    # Run scans concurrently across a thread pool
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(check_port, target_ip, port)
            for port in range(start_port, end_port + 1)
        ]

        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                print(f"[+] Port {res['port']:<5} | Service: {res['service']:<12} | Banner: {res['banner']}")

    elapsed_time = round(time.time() - start_time, 2)
    open_ports.sort(key=lambda x: x["port"])

    print("=" * 65)
    print("Scan Summary:")
    print(f"  - Total Scanned : {total_ports}")
    print(f"  - Open Ports    : {len(open_ports)}")
    print(f"  - Closed/Filtered: {total_ports - len(open_ports)}")
    print(f"  - Time Elapsed  : {elapsed_time}s\n")

    if open_ports:
        print(f"{'PORT':<8} {'SERVICE':<15} {'BANNER / IDENTIFIER'}")
        print("-" * 65)
        for item in open_ports:
            print(f"{item['port']:<8} {item['service']:<15} {item['banner']}")
    else:
        print("[-] No open ports discovered in the specified range.")

if __name__ == "__main__":
    try:
        target = input("Enter target (IP or domain): ").strip()
        start_port = int(input("Enter start port (e.g., 1): ").strip())
        end_port = int(input("Enter end port (e.g., 1024): ").strip())

        if start_port < 1 or end_port > 65535 or start_port > end_port:
            print("[-] Invalid port range (must be between 1 and 65535).")
            sys.exit(1)

        scan_ports(target, start_port, end_port)
    except KeyboardInterrupt:
        print("\n[-] Scan interrupted by user.")
        sys.exit(0)
