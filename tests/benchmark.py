import concurrent.futures
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import requests

from impersonate_proxy import main as proxy


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress logs for speed

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"OK")


def start_mock_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return f"http://127.0.0.1:{port}", server


def run_benchmark():
    target_url, mock_server = start_mock_server()

    # Start proxy
    proxy_port = 38899
    proxy_url = f"http://127.0.0.1:{proxy_port}"
    with tempfile.TemporaryDirectory() as tmpdir:
        proxy._init_ca(tmpdir)
        proxy_server = ThreadingHTTPServer(("127.0.0.1", proxy_port), proxy.ProxyHandler)
        proxy_thread = threading.Thread(target=proxy_server.serve_forever, daemon=True)
        proxy_thread.start()

        # Wait for proxy
        time.sleep(0.5)

        num_requests = 100
        print(f"Starting benchmark: {num_requests} concurrent requests through proxy...")

        start_time = time.time()

        def send_req():
            try:
                r = requests.get(target_url, proxies={"http": proxy_url}, timeout=5)
                return r.status_code == 200
            except Exception:
                return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = list(executor.map(lambda _: send_req(), range(num_requests)))

        end_time = time.time()
        duration = end_time - start_time
        success_count = sum(1 for r in results if r)

        print(f"Completed {num_requests} requests in {duration:.4f} seconds")
        print(f"Success rate: {success_count}/{num_requests}")
        print(f"Throughput: {num_requests / duration:.2f} requests/second")

        proxy_server.shutdown()
        mock_server.shutdown()


if __name__ == "__main__":
    run_benchmark()
