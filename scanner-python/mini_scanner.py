#!/usr/bin/env python3
"""
mini_scanner.py
Usage example:
  python3 mini_scanner.py --target 192.168.56.101 --ports 1-1024 --threads 100 --output results.json
"""

import socket
import argparse
import threading
import queue
import json
import csv

def parse_ports(pstr):
    ports = set()
    for part in pstr.split(','):
        if '-' in part:
            a,b = part.split('-')
            ports.update(range(int(a), int(b)+1))
        else:
            ports.add(int(part))
    return sorted(ports)

def banner_grab(ip, port, timeout):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        try:
            s.send(b'\r\n')
        except:
            pass
        data = s.recv(1024)
        s.close()
        return data.decode(errors='ignore').strip()
    except Exception:
        return ""

def worker(q, results, timeout):
    while True:
        try:
            ip, port = q.get_nowait()
        except queue.Empty:
            break
        sock = socket.socket()
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            state = "open"
            banner = banner_grab(ip, port, timeout)
        except Exception:
            state = "closed"
            banner = ""
        finally:
            try: sock.close()
            except: pass
        results.append({"ip": ip, "port": port, "state": state, "banner": banner})
        q.task_done()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="IP (single)")
    parser.add_argument("--ports", default="1-1024", help="ports, ex: 22,80,443 or 1-1000")
    parser.add_argument("--threads", type=int, default=50)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--output", default="results.json")
    parser.add_argument("--csv", action="store_true")
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    ip = args.target

    q = queue.Queue()
    for p in ports:
        q.put((ip, p))

    results = []
    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=worker, args=(q, results, args.timeout))
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()  # wait all
    # write JSON
    with open(args.output, "w") as f:
        json.dump(results, f, indent=2)

    if args.csv:
        csv_file = args.output.rsplit('.',1)[0] + ".csv"
        with open(csv_file, "w", newline='') as f:
            w = csv.writer(f)
            w.writerow(["ip","port","state","banner"])
            for r in results:
                w.writerow([r["ip"], r["port"], r["state"], r["banner"]])

    print(f"Done. {len(results)} results -> {args.output}")

if __name__ == "__main__":
    main()
