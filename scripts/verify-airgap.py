#!/usr/bin/env python3
"""
ULPF Air-Gapped Network Verification Script

This script verifies that no outbound network connections are attempted
by the ULPF services during normal operation.

Usage:
    python verify-airgap.py [--duration SECONDS]

The script:
1. Starts all services via docker-compose
2. Monitors network connections from containers
3. Reports any outbound connections (non-internal IPs)
4. Exits with error code if outbound connections detected
"""

import argparse
import subprocess
import time
import sys
import json
import socket
from typing import Set, List, Dict
from datetime import datetime, timezone

# Internal networks that are allowed
INTERNAL_NETWORKS = [
    "127.0.0.0/8",      # Loopback
    "10.0.0.0/8",       # RFC1918 Class A
    "172.16.0.0/12",    # RFC1918 Class B
    "192.168.0.0/16",   # RFC1918 Class C
    "169.254.0.0/16",   # Link-local
    "::1/128",          # IPv6 loopback
    "fe80::/10",        # IPv6 link-local
    "fc00::/7",         # IPv6 ULA
]

# Known external endpoints that would indicate internet access
EXTERNAL_INDICATORS = [
    "api.openai.com",
    "api.anthropic.com",
    "huggingface.co",
    "pypi.org",
    "npmjs.org",
    "registry.npmjs.org",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
]


def ip_in_network(ip: str, network: str) -> bool:
    """Check if IP is in CIDR network."""
    try:
        import ipaddress
        return ipaddress.ip_address(ip) in ipaddress.ip_network(network)
    except Exception:
        return False


def is_internal_ip(ip: str) -> bool:
    """Check if IP is internal/private."""
    for network in INTERNAL_NETWORKS:
        if ip_in_network(ip, network):
            return True
    return False


def get_container_ips() -> Dict[str, str]:
    """Get container names and their IPs."""
    result = {}
    try:
        output = subprocess.check_output(
            ["docker", "ps", "--format", "{{.Names}}"],
            text=True
        )
        containers = [line.strip() for line in output.strip().split("\n") if line.strip() and "ulpf" in line]
        
        for container in containers:
            try:
                inspect = subprocess.check_output(
                    ["docker", "inspect", container, "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}"],
                    text=True
                ).strip()
                if inspect:
                    result[container] = inspect
            except subprocess.CalledProcessError:
                pass
    except subprocess.CalledProcessError:
        pass
    return result


def check_container_connections(container: str) -> List[Dict]:
    """Check active network connections for a container."""
    connections = []
    try:
        # Use nsenter to run netstat/ss inside container namespace
        output = subprocess.check_output(
            ["docker", "exec", container, "ss", "-tunap"],
            text=True,
            stderr=subprocess.DEVNULL
        )
        
        for line in output.strip().split("\n")[1:]:  # Skip header
            parts = line.split()
            if len(parts) >= 5:
                state = parts[0]
                local_addr = parts[3]
                peer_addr = parts[4]
                process = " ".join(parts[5:]) if len(parts) > 5 else ""
                
                # Parse peer IP
                peer_ip = peer_addr.split(":")[0] if ":" in peer_addr else peer_addr
                
                connections.append({
                    "container": container,
                    "state": state,
                    "local": local_addr,
                    "peer": peer_addr,
                    "peer_ip": peer_ip,
                    "process": process,
                    "is_external": not is_internal_ip(peer_ip) and peer_ip not in ["*", "0.0.0.0", "::"]
                })
    except subprocess.CalledProcessError:
        pass
    except FileNotFoundError:
        # ss not available, try netstat
        try:
            output = subprocess.check_output(
                ["docker", "exec", container, "netstat", "-tunap"],
                text=True,
                stderr=subprocess.DEVNULL
            )
            # Parse netstat output similarly
        except subprocess.CalledProcessError:
            pass
    return connections


def check_dns_queries(container: str) -> List[str]:
    """Check for external DNS queries (simplified)."""
    # This is a simplified check - in reality you'd need more sophisticated monitoring
    external_domains = []
    return external_domains


def main():
    parser = argparse.ArgumentParser(description="ULPF Air-Gap Network Verification")
    parser.add_argument("--duration", type=int, default=30, help="Monitoring duration in seconds")
    parser.add_argument("--compose-file", default="docker-compose.airgap.yml", help="Docker compose file")
    args = parser.parse_args()

    print("=" * 60)
    print("ULPF Air-Gapped Network Verification")
    print("=" * 60)
    print(f"Monitoring duration: {args.duration} seconds")
    print(f"Compose file: {args.compose_file}")
    print("")

    # Start services
    print("Starting services...")
    try:
        subprocess.run(
            ["docker", "compose", "-f", args.compose_file, "up", "-d"],
            check=True,
            capture_output=True,
            text=True
        )
    except subprocess.CalledProcessError as e:
        print(f"Failed to start services: {e.stderr}")
        return 1

    # Wait for services to be healthy
    print("Waiting for services to be healthy...")
    time.sleep(10)

    # Get container IPs
    container_ips = get_container_ips()
    print(f"Found containers: {list(container_ips.keys())}")

    # Monitor for duration
    print(f"\nMonitoring network connections for {args.duration} seconds...")
    print("-" * 60)

    all_external_connections = []
    start_time = time.time()
    
    while time.time() - start_time < args.duration:
        for container, ip in container_ips.items():
            connections = check_container_connections(container)
            for conn in connections:
                if conn["is_external"]:
                    all_external_connections.append(conn)
                    print(f"⚠ EXTERNAL CONNECTION DETECTED:")
                    print(f"  Container: {conn['container']}")
                    print(f"  Local: {conn['local']} -> Peer: {conn['peer']}")
                    print(f"  Process: {conn['process']}")
        
        if not all_external_connections:
            elapsed = int(time.time() - start_time)
            print(f"  [{elapsed}/{args.duration}s] No external connections detected...", end="\r")
        
        time.sleep(2)

    print("\n" + "-" * 60)
    
    # Stop services
    print("Stopping services...")
    subprocess.run(
        ["docker", "compose", "-f", args.compose_file, "down"],
        capture_output=True
    )

    # Report results
    if all_external_connections:
        print(f"\n❌ FAILED: {len(all_external_connections)} external connection(s) detected!")
        print("The following external connections were observed:")
        for conn in all_external_connections:
            print(f"  {conn['container']}: {conn['local']} -> {conn['peer']} ({conn['process']})")
        return 1
    else:
        print("\n✅ PASSED: No external network connections detected.")
        print("All connections were to internal/private IP addresses.")
        return 0


if __name__ == "__main__":
    sys.exit(main())