# Offline test: fake MISP API + fake Wazuh queue socket. Run: python3 tests/test_custom_misp.py
import sys, os, json, socket, threading, tempfile, importlib.util
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
tmp = tempfile.mkdtemp(); sockpath = os.path.join(tmp, 'queue')
os.environ['WAZUH_QUEUE_SOCKET'] = sockpath
rx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); rx.bind(sockpath); rx.settimeout(0.5)
spec = importlib.util.spec_from_file_location('cm', os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'integrations', 'custom-misp.py'))
cm = importlib.util.module_from_spec(spec); spec.loader.exec_module(cm)
BAD = {'tikonam.com', '8.8.4.4', 'a'*64}
seen = []
class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        seen.append((self.path, self.headers.get('Authorization'), body['value']))
        if self.headers.get('Authorization') != 'k': self.send_response(403); self.end_headers(); return
        attrs = [{'event_id': '42', 'category': 'Network activity', 'value': body['value'], 'type': 'domain'}] if body['value'] in BAD else []
        self.send_response(200); self.send_header('Content-Type','application/json'); self.end_headers()
        self.wfile.write(json.dumps({'response': {'Attribute': attrs}}).encode())
    def log_message(self, *a): pass
srv = ThreadingHTTPServer(('127.0.0.1', 8097), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
agent = {'id': '003', 'name': 'WIN10-LAB', 'ip': '203.0.113.10'}
def win(group, **ed): return {'rule': {'id': '61650', 'description': 'Sysmon', 'groups': ['windows', 'sysmon', group]}, 'agent': agent, 'data': {'win': {'eventdata': ed}}}
cases = [
  ('dns hit',          win('sysmon_event_22', queryName='TIKONAM.com.'), 'k'),
  ('dns clean',        win('sysmon_event_22', queryName='example.org'), 'k'),
  ('process hash hit', win('sysmon_event1', hashes='SHA1=abc,MD5=def,SHA256=' + 'A'*64 + ',IMPHASH=x'), 'k'),
  ('public ip hit',    win('sysmon_event3', destinationIp='8.8.4.4', destinationIsIpv6='false'), 'k'),
  ('private ip skip',  win('sysmon_event3', destinationIp='169.254.10.10'), 'k'),
  ('ipv6 no crash',    win('sysmon_event3', destinationIp='2606:4700::1111', destinationIsIpv6='true'), 'k'),
  ('missing field',    win('sysmon_event1'), 'k'),
  ('fim new file hit', {'rule': {'id': '554', 'groups': ['ossec', 'syscheck', 'syscheck_entry_added']}, 'agent': agent, 'syscheck': {'path': '/tmp/x', 'sha256_after': 'a'*64}}, 'k'),
  ('wrong api key',    win('sysmon_event_22', queryName='tikonam.com'), 'WRONG'),
]
for name, alert, key in cases:
    p = os.path.join(tmp, 'a.json'); json.dump(alert, open(p, 'w'))
    before = len(seen)
    rc = cm.main(['x', p, key, 'http://127.0.0.1:8097'])
    try: msg = rx.recv(65535).decode()
    except socket.timeout: msg = ''
    queried = len(seen) > before
    print(f'{name:18} rc={rc} queried={queried!s:5} -> ' + (msg[:120] if msg else '(no event)'))
srv.shutdown()
