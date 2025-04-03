import os, re, time, socks, socket, sqlite3, requests, urllib3, argparse, json, threading, subprocess, configparser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from contextlib import closing
import xml.etree.ElementTree as ET
from urllib3.exceptions import ProxyError, SSLError, ConnectTimeoutError, ReadTimeoutError, NewConnectionError
import logging
from urllib3 import PoolManager

# Setup
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
config = configparser.ConfigParser(); config.read('config.ini')
os.system('ulimit -n 80000'); urllib3.disable_warnings()

# Argument parsing
parser = argparse.ArgumentParser(description='Proxy checker script')
parser.add_argument('-url', type=str, help='API URL to get proxies')
parser.add_argument('-sip', type=str, help='Self IP')
parser.add_argument('-ping', action='store_true', help='Ping test before checking')
parser.add_argument('-db', action='store_true', help='Recheck proxies in db')
parser.add_argument('-clean', action='store_true', help='Clean old proxies in db')
parser.add_argument('-txt', action='store_true', help='Save results in txt files')
parser.add_argument('-scan', action='store_true', help='Check scan results')
parser.add_argument('-type', nargs='+', choices=['http','https','socks4','socks5'])
parser.add_argument('-mass', type=str, help='Path to masscan XML')
parser.add_argument('-list', action='store_true', help='Check proxy from open sources')
parser.add_argument('-targets', action='store_true', help='Check proxy from targets.txt')
parser.add_argument('-s', nargs='+', help='Check multiple server:port')
parser.add_argument('-w', type=int, default=100, help='Worker threads count')
parser.add_argument('-t', type=int, default=4, help='Timeout in seconds')
args = parser.parse_args()

proxy_types = args.type if args.type else ['http','https','socks4','socks5']
all_checked_proxies = {}

class Ping:
    def __init__(self, host):
        self.host, self.response_time, self.is_running = host, None, True
        threading.Thread(target=self.run, daemon=True).start()
    def run(self):
        while self.is_running:
            try:
                output = subprocess.check_output(['ping','-c','1',self.host])
                if 'time=' in (line := output.decode().splitlines()[-1]):
                    self.response_time = float(line.split('time=')[1].split()[0])
            except: self.response_time = None
            time.sleep(1)
    def get_response_time(self): return self.response_time
    def stop(self): self.is_running = False

if args.ping: pinger = Ping('1.1.1.1')

sip = args.sip if args.sip else next((data.get('origin') for _ in iter(int,1) if (data:=requests.get('https://httpbin.org/ip').json())))

def process_page(page):
    try:
        content = requests.get(f"https://www.freeproxy.world/?page={page}").text
        return [f"{ip}:{port}" for ip, port in zip(re.findall(r'((\d{1,3}\.){3}\d{1,3}',content), re.findall(r'port=(\d+)',content))]
    except: return []

http_pool = PoolManager(maxsize=10)

def check_proxy(proxy, proxy_type):
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    try:
        proxy_host, proxy_port = proxy.split(':')
        if proxy_type in ['http','https']:
            http = urllib3.ProxyManager(f"{proxy_type}://{proxy_host}:{proxy_port}", timeout=urllib3.Timeout(connect=args.t,read=args.t), retries=False, cert_reqs='CERT_NONE')
            start_time = time.time()
            response = http.request('GET','https://httpbin.org/ip',preload_content=False)
            data, response_time = json.loads(response.data.decode()), time.time()-start_time
            response.release_conn()
        else:
            socks.set_default_proxy(socks.SOCKS4 if proxy_type=='socks4' else socks.SOCKS5, proxy_host, int(proxy_port))
            socket.socket = socks.socksocket
            r = requests.get('https://httpbin.org/ip',timeout=args.t,verify=False,headers={'X-Forwarded-For':proxy_host})
            data, response_time = r.json(), r.elapsed.total_seconds()
        
        if not any(origin==sip for origin in data.get('origin').split(', ')):
            with closing(sqlite3.connect(config['database']['path'],timeout=30)) as conn:
                conn.cursor().execute(f'''INSERT OR REPLACE INTO {proxy_type} VALUES (?,?,?)''', 
                                    (f'{proxy_host}:{proxy_port}', round(response_time,2), current_time))
                conn.commit()
            logging.info(f"Successful proxy: {proxy_host}:{proxy_port} ({response_time:.2f}s)")
            return f'{proxy_host}:{proxy_port}', response_time, current_time
    except Exception as e:
        if "Too many open files" in str(e): logging.warning("Too many open files error")
    finally:
        socks.set_default_proxy()
        socket.socket = socket.socket
    return None

def get_db_connection(): return sqlite3.connect(config['database']['path'], timeout=30)

def load_urls_from_file(file_path):
    with open(file_path) as f: return f.read().splitlines()

def add_sources(start_page=1, end_page=200, num_threads=10):
    ip_port_pattern = re.compile(r'((\d{1,3}\.){3}\d{1,3}|port=\d+)')
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(process_page, page): page for page in range(start_page,end_page+1)}
        return {proxy for future in as_completed(futures) for proxy in future.result()}

def main_loop():
    while True:
        ip_ports = set()
        
        # Collect proxies from all sources
        if args.url: 
            try: ip_ports.update(requests.get(args.url).text.splitlines())
            except Exception as e: logging.error(f"Error fetching from URL: {e}")
        if args.s: ip_ports.update(args.s)
        if args.targets:
            try: ip_ports.update(open('targets.txt').read().splitlines())
            except Exception as e: logging.error(f"Error reading targets.txt: {e}")
        if args.list:
            ip_ports.update(add_sources())
            try: ip_ports.update(proxy for url in load_urls_from_file('urls.txt') for proxy in requests.get(url).text.splitlines())
            except Exception as e: logging.error(f"Error loading URLs: {e}")
        if args.mass:
            try: ip_ports.update(f"{host.find('address').get('addr')}:{port.get('portid')}" 
                              for host in ET.parse(args.mass).getroot().findall('host') 
                              for port in host.findall('ports/port'))
            except Exception as e: logging.error(f"Error parsing masscan: {e}")
        if args.db:
            with closing(get_db_connection()) as conn:
                for proxy_type in proxy_types:
                    conn.cursor().execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} 
                                            (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
                    ip_ports.update(proxy[0] for proxy in conn.cursor().execute(f'''SELECT proxy FROM {proxy_type}''').fetchall())

        logging.info(f'Total proxies to check: {len(ip_ports)}')
        
        # Check proxies
        for proxy_type in proxy_types:
            logging.info(f'Checking {proxy_type} proxies...')
            with closing(get_db_connection()) as conn:
                conn.cursor().execute(f'''CREATE TABLE IF NOT EXISTS {proxy_type} 
                                        (proxy TEXT PRIMARY KEY, response_time REAL, last_checked TEXT)''')
                conn.commit()
            
            with ThreadPoolExecutor(max_workers=args.w) as executor:
                futures = {executor.submit(check_proxy, p, proxy_type): p for p in ip_ports}
                all_checked_proxies[proxy_type] = sorted((r for f in as_completed(futures) if (r:=f.result())), key=lambda x:x[1])
                
                if args.clean:
                    with closing(get_db_connection()) as conn:
                        conn.cursor().executemany(f'''DELETE FROM {proxy_type} WHERE proxy=?''', 
                                                 [(p,) for p in {futures[f] for f in futures if not f.result()}])
                        conn.commit()
                
                if args.scan:
                    with closing(get_db_connection()) as conn:
                        conn.cursor().executemany('''DELETE FROM _scan_results WHERE ip_port=?''', [(p,) for p in ip_ports])
                        conn.commit()

        # Save results
        if args.txt:
            os.makedirs('txt', exist_ok=True)
            for proxy_type, proxies in all_checked_proxies.items():
                with open(f'txt/{proxy_type}.txt','w') as f: 
                    f.write('\n'.join(p[0] for p in proxies))
        
        logging.info("Finished checking. Restarting...")
        time.sleep(1)

if __name__ == '__main__': main_loop()
