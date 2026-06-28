import sys

# TCP State mappings based on the Linux kernel (include/net/tcp_states.h)
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING"
}

def hex_to_ip_port(hex_string):
    """Converts a little-endian hex IP and hex port into human readable format."""
    hex_ip, hex_port = hex_string.split(':')
    
    # Reverse the byte order for the IP (Little Endian)
    ip_blocks = [str(int(hex_ip[i:i+2], 16)) for i in range(0, 8, 2)]
    ip_addr = ".".join(reversed(ip_blocks))
    
    # Convert port directly from hex to decimal
    port = int(hex_port, 16)
    
    return f"{ip_addr}:{port}"

def parse_tcp_file(file_path):
    print(f"{'Local Address':<25} {'Remote Address':<25} {'State'}")
    print("-" * 65)
    
    try:
        with open(file_path, 'r') as f:
            lines = f.readlines()
            
        # Skip the header line
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
                
            local_address = hex_to_ip_port(parts[1])
            remote_address = hex_to_ip_port(parts[2])
            state_hex = parts[3]
            state = TCP_STATES.get(state_hex, f"UNKNOWN ({state_hex})")
            
            print(f"{local_address:<25} {remote_address:<25} {state}")
            
    except FileNotFoundError:
        print(f"File not found: {file_path}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 parse_tcp.py <path_to_tcp_file>")
        sys.exit(1)
        
    parse_tcp_file(sys.argv[1])
