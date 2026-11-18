"""Servico de nuvem (simulado): recebe lotes do no de borda e reconcilia de forma idempotente (edge, seq)."""
import json, os, sqlite3, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
DB = os.environ.get("CLOUD_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "cloud.db"))
os.makedirs(os.path.dirname(DB), exist_ok=True)
con = sqlite3.connect(DB, check_same_thread=False)
con.execute("CREATE TABLE IF NOT EXISTS readings(edge TEXT, seq INTEGER, device TEXT, ts REAL, payload TEXT, recv REAL, PRIMARY KEY(edge,seq))")
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.headers.get("X-Edge-Id") != "edge-ubs": self.send_response(403); self.end_headers(); return
        d = json.loads(self.rfile.read(int(self.headers["Content-Length"]))); ins = dup = 0
        for seq, dev, ts, pl in d["rows"]:
            cur = con.execute("INSERT OR IGNORE INTO readings VALUES(?,?,?,?,?,?)", (d["edge"], seq, dev, ts, pl, time.time()))
            ins += cur.rowcount; dup += 1 - cur.rowcount
        con.commit(); out = json.dumps({"inserted": ins, "duplicates": dup}).encode()
        self.send_response(200); self.end_headers(); self.wfile.write(out)
    def log_message(self, *a): pass
if __name__ == "__main__": ThreadingHTTPServer(("127.0.0.1", 8090), H).serve_forever()
