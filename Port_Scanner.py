# Port Scanner (concurrent, safe defaults)
# Scans a range of TCP ports on a target IP or hostname and reports open ports.

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def resolve_target(target):
    """Resolve a hostname to an IP, or return the IP if already an IP string."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None

def scan_single_port(target_ip, port, timeout=0.5):
    """
    Attempt to connect to a single TCP port.
    Returns (port, True) if open, (port, False) otherwise.
    """
    try:
        # Create a TCP socket, attempt connect, then close automatically
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)                  # short timeout to avoid long waits
            result = sock.connect_ex((target_ip, port))  # 0 == success (open)
            return (port, result == 0)
    except Exception:
        return (port, False)

def scan_ports_concurrent(target, start_port=1, end_port=1024, max_workers=100, timeout=0.5):
    """
    Scan ports in the inclusive range [start_port, end_port] on target (hostname or IP).
    Uses a thread pool to speed up scanning.
    """
    target_ip = resolve_target(target)
    if not target_ip:
        print(f"Error: could not resolve target '{target}'.")
        return

    # Validate port bounds
    start_port = max(1, int(start_port))
    end_port = min(65535, int(end_port))
    if start_port > end_port:
        start_port, end_port = end_port, start_port  # swap if user mixed order

    print(f"Scanning {target} ({target_ip}) ports {start_port}..{end_port} with up to {max_workers} workers...\n")

    open_ports = []

    # Use ThreadPoolExecutor to scan ports concurrently
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scan tasks
        futures = {executor.submit(scan_single_port, target_ip, port, timeout): port
                   for port in range(start_port, end_port + 1)}

        try:
            for future in as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    print(f"Port {port} is open")
                    open_ports.append(port)
        except KeyboardInterrupt:
            print("\nScan interrupted by user. Shutting down threads...")
            executor.shutdown(wait=False)
            return

    # Summary
    if open_ports:
        open_ports.sort()
        print("\nOpen ports:", ", ".join(str(p) for p in open_ports))
    else:
        print("\nNo open ports found in the scanned range.")

# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    target = input("Enter target IP or hostname (e.g., 192.168.1.10 or example.com): ").strip()
    if not target:
        print("No target entered. Exiting.")
        raise SystemExit(1)

    # Optional: allow user to specify a port range like "20-1024"
    port_range = input("Enter port range (start-end) [default 1-1024]: ").strip() or "1-1024"
    try:
        start_str, end_str = port_range.split("-", 1)
        start_port = int(start_str)
        end_port = int(end_str)
    except Exception:
        print("Invalid port range format. Use start-end (e.g., 1-1024).")
        raise SystemExit(1)

    # Optional: smaller pool for low-resource systems
    try:
        workers = int(input("Enter max concurrent workers [default 100]: ").strip() or "100")
        workers = max(1, min(1000, workers))  # clamp to reasonable bounds
    except ValueError:
        workers = 100

    # Optional: timeout per port attempt
    try:
        timeout = float(input("Enter timeout per port (seconds) [default 0.5]: ").strip() or "0.5")
        timeout = max(0.05, min(5.0, timeout))
    except ValueError:
        timeout = 0.5

    scan_ports_concurrent(target, start_port, end_port, max_workers=workers, timeout=timeout)
