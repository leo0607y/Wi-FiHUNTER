import os, math, time, socket, struct, threading, ipaddress, re
import urllib.request
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, BaseMacLookup
from concurrent.futures import ThreadPoolExecutor, as_completed

BaseMacLookup.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")

MDNS_TIMEOUT = 5.0

# ── Apple モデル識別子 → 機種名 ────────────────────────────────────────────
APPLE_MODELS = {
    'iPhone17,1':'iPhone 16 Pro',    'iPhone17,2':'iPhone 16 Pro Max',
    'iPhone17,3':'iPhone 16',        'iPhone17,4':'iPhone 16 Plus',
    'iPhone16,1':'iPhone 15 Pro',    'iPhone16,2':'iPhone 15 Pro Max',
    'iPhone15,4':'iPhone 15',        'iPhone15,5':'iPhone 15 Plus',
    'iPhone15,2':'iPhone 14 Pro',    'iPhone15,3':'iPhone 14 Pro Max',
    'iPhone14,7':'iPhone 14',        'iPhone14,8':'iPhone 14 Plus',
    'iPhone14,2':'iPhone 13 Pro',    'iPhone14,3':'iPhone 13 Pro Max',
    'iPhone14,4':'iPhone 13 mini',   'iPhone14,5':'iPhone 13',
    'iPhone13,1':'iPhone 12 mini',   'iPhone13,2':'iPhone 12',
    'iPhone13,3':'iPhone 12 Pro',    'iPhone13,4':'iPhone 12 Pro Max',
    'iPad13,18':'iPad 10th',         'iPad14,1':'iPad mini 6',
    'iPad14,3':'iPad Air 5',         'iPad16,3':'iPad Air 13 M2',
    'iPad14,5':'iPad Pro 11 M2',     'iPad14,6':'iPad Pro 12.9 M2',
    'Mac14,2':'MacBook Air M2',      'Mac14,7':'MacBook Pro 13 M2',
    'Mac15,3':'MacBook Pro 14 M3',   'Mac15,6':'MacBook Pro 16 M3',
    'Mac14,3':'Mac mini M2',
    'Watch7,1':'Apple Watch S9 40', 'Watch7,2':'Apple Watch S9 44',
    'Watch7,3':'Apple Watch Ultra 2','Watch7,5':'Apple Watch SE2',
    'AudioAccessory5,1':'HomePod 2', 'AudioAccessory6,1':'HomePod mini',
    'AppleTV14,1':'Apple TV 4K 3rd',
}

PORT_LABELS = {22:'SSH', 80:'HTTP', 139:'NetBIOS', 443:'HTTPS',
               445:'SMB', 3389:'RDP', 5000:'UPnP', 8080:'HTTP-alt',
               62078:'Apple-sync', 9100:'Printer'}


# ── ネットワーク検出 ─────────────────────────────────────────────────────────

def get_active_network():
    try:
        iface    = scapy.conf.iface
        local_ip = scapy.get_if_addr(str(iface))
        if local_ip and local_ip not in ('0.0.0.0', '127.0.0.1'):
            for entry in scapy.conf.route.routes:
                network, netmask, _, interface, address = (
                    entry[0], entry[1], entry[2], entry[3], entry[4])
                if address == local_ip and network != 0 and netmask != 0:
                    prefix   = bin(netmask & 0xFFFFFFFF).count('1')
                    net_addr = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                    return str(net_addr), local_ip, str(iface)
    except Exception as e:
        print(f"[警告] アクティブインターフェースの自動取得に失敗: {e}")
    return "192.168.1.0/24", "192.168.1.x", "Default"


# ── ARP スキャン ─────────────────────────────────────────────────────────────

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered    = scapy.srp(broadcast / arp_request, timeout=3, retry=1, verbose=False)[0]
    devices     = [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]
    devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    return devices


# ── ICMP TTL 一括取得 ────────────────────────────────────────────────────────

def get_ttl_batch(ip_list, timeout=2):
    """全デバイスに ICMP Echo を一括送信して TTL を収集する"""
    ttl_map = {}
    try:
        pkts     = [scapy.IP(dst=ip)/scapy.ICMP() for ip in ip_list]
        answered, _ = scapy.sr(pkts, timeout=timeout, verbose=False)
        for sent, recv in answered:
            ttl_map[sent.dst] = recv.ttl
    except Exception:
        pass
    return ttl_map


# ── ポートスキャン ────────────────────────────────────────────────────────────

def quick_port_scan(ip, ports=(22, 80, 139, 443, 445, 3389, 5000, 62078, 9100), timeout=0.35):
    """主要ポートの開放チェックを行い、開いているポート番号リストを返す"""
    open_ports = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports


# ── OS / デバイス種別 推定 ───────────────────────────────────────────────────

def infer_os(ttl, vendor, hostname, open_ports):
    v = (vendor   or '').lower()
    h = (hostname or '').lower()
    p = set(open_ports or [])

    if 'apple' in v:
        if any(x in h for x in ('iphone', 'ipod')):   return 'iOS'
        if 'ipad'  in h:                               return 'iPadOS'
        return 'macOS'

    if {445, 3389} & p or h.startswith(('desktop-', 'laptop-')):
        return 'Windows'
    if 22 in p and 'apple' not in v:
        return 'Linux'

    if ttl:
        if   ttl >= 110: return 'Windows'
        elif ttl >= 50:
            if 'samsung' in v or 'android' in h: return 'Android'
            return 'Linux / macOS'

    if 'samsung'  in v: return 'Android (推定)'
    if 'raspberr' in v: return 'Linux (Raspberry Pi)'
    return '不明'


def infer_device_type(ip, vendor, hostname, os_hint, open_ports):
    v = (vendor   or '').lower()
    h = (hostname or '').lower()
    p = set(open_ports or [])

    if any(x in v for x in ('asus', 'buffalo', 'nec', 'tp-link', 'netgear', 'cisco', 'yamaha')):
        if ip.endswith('.1') or any(x in h for x in ('router', 'gateway', 'ap', 'rt-')):
            return 'ルーター / AP'

    if 'raspberr' in v or 'raspberrypi' in h: return 'Raspberry Pi'
    if 'apple' in v:
        if 'iphone' in h:  return 'iPhone'
        if 'ipad'   in h:  return 'iPad'
        if any(x in h for x in ('mac', 'book')): return 'Mac'
        if 'apple watch' in h or 'watch' in h:   return 'Apple Watch'
        if 'appletv' in h:   return 'Apple TV'
        if 'homepod' in h:   return 'HomePod'
        return 'Apple デバイス'

    if 3389 in p or h.startswith('desktop-'):  return 'Windows デスクトップ'
    if h.startswith('laptop-') or 'laptop' in h: return 'Windows ノートPC'
    if 445 in p and os_hint == 'Windows':         return 'Windows PC'

    if 9100 in p:  return 'プリンター'
    if 22   in p and 'buffalo' not in v: return 'Linux サーバー'
    if 'samsung' in v:   return 'Samsung (スマホ / TV)'
    if 'sony'    in v:   return 'Sony デバイス'
    if any(x in v for x in ('ampak', 'azurewave', 'espressif', 'realtek semiconductor')):
        return 'IoT / 組み込み'
    if 'buffalo' in v:   return 'NAS / 周辺機器'

    return '不明'


# ── SSDP 一括収集 ────────────────────────────────────────────────────────────

def collect_ssdp_info(ip_set, timeout=4):
    """
    SSDP マルチキャスト M-SEARCH で機器情報を収集し、
    LOCATION URL の XML から製品名・メーカーを取得する。
    """
    locations = {}   # ip -> url

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)
        msg = ('M-SEARCH * HTTP/1.1\r\n'
               'HOST: 239.255.255.250:1900\r\n'
               'MAN: "ssdp:discover"\r\n'
               'MX: 2\r\n'
               'ST: ssdp:all\r\n\r\n').encode()
        sock.sendto(msg, ('239.255.255.250', 1900))

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip in ip_set and src_ip not in locations:
                    text = data.decode('utf-8', errors='replace')
                    for line in text.split('\r\n'):
                        if line.lower().startswith('location:'):
                            locations[src_ip] = line.split(':', 1)[1].strip()
                            break
            except socket.timeout:
                continue
        sock.close()
    except Exception:
        pass

    # XML を並列取得
    ssdp_info = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        fut_map = {ex.submit(_fetch_ssdp_xml, url): ip for ip, url in locations.items()}
        for fut in as_completed(fut_map):
            ip   = fut_map[fut]
            info = fut.result()
            if info:
                ssdp_info[ip] = info
    return ssdp_info


def _fetch_ssdp_xml(url, timeout=3):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Wi-FiHUNTER/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            xml = r.read().decode('utf-8', errors='replace')
        info = {}
        for tag in ('friendlyName', 'modelName', 'modelNumber', 'manufacturer', 'deviceType'):
            m = re.search(fr'<{tag}[^>]*>\s*(.*?)\s*</{tag}>', xml, re.I | re.S)
            if m:
                info[tag] = m.group(1).strip()[:50]
        return info or None
    except Exception:
        return None


# ── DNS / mDNS ユーティリティ ─────────────────────────────────────────────

def _encode_dns_name(name):
    encoded = b''
    for label in name.split('.'):
        if label:
            encoded += bytes([len(label)]) + label.encode('utf-8')
    return encoded + b'\x00'


def _decode_dns_name(data, offset, depth=0):
    labels = []
    if depth > 10:
        return '', offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _decode_dns_name(data, ptr, depth + 1)
            labels.append(sub)
            offset += 2
            return '.'.join(labels), offset
        offset += 1
        raw = data[offset:offset + length]
        try:
            labels.append(raw.decode('utf-8'))
        except UnicodeDecodeError:
            labels.append(raw.decode('latin-1', errors='replace'))
        offset += length
    return '.'.join(labels), offset


def _extract_mdns_info(data, src_ip):
    """mDNS パケットから (hostname, model_id) を抽出する"""
    try:
        if len(data) < 12:
            return None, None
        qdcount = int.from_bytes(data[4:6],  'big')
        ancount = int.from_bytes(data[6:8],  'big')
        nscount = int.from_bytes(data[8:10], 'big')
        arcount = int.from_bytes(data[10:12],'big')
        if ancount + nscount + arcount == 0:
            return None, None
        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_dns_name(data, offset)
            offset += 4
        hostname = None
        model_id = None
        for _ in range(ancount + nscount + arcount):
            if offset >= len(data):
                break
            rec_name, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype    = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 8
            rdlength = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 2
            rdata    = data[offset:offset + rdlength]
            if rtype == 12:   # PTR
                ptr, _ = _decode_dns_name(data, offset)
                if 'in-addr.arpa' in rec_name:
                    n = ptr.removesuffix('.local').rstrip('.')
                    if n and not hostname:
                        hostname = n
                elif '_device-info' in rec_name or '_tcp' in rec_name:
                    for suf in ('._device-info._tcp.local', '._tcp.local', '.local'):
                        if ptr.endswith(suf):
                            n = ptr[:-len(suf)].rstrip('.')
                            if n and not hostname:
                                hostname = n
                            break
            elif rtype == 1 and rdlength == 4:   # A
                if socket.inet_ntoa(rdata) == src_ip:
                    n = rec_name.removesuffix('.local').rstrip('.')
                    if n and '._' not in n and not hostname:
                        hostname = n
            elif rtype == 16:   # TXT
                off2 = 0
                while off2 < len(rdata):
                    tl = rdata[off2]; off2 += 1
                    if off2 + tl > len(rdata):
                        break
                    txt = rdata[off2:off2 + tl].decode('utf-8', errors='ignore')
                    off2 += tl
                    if txt.lower().startswith('model='):
                        model_id = txt[6:].strip()
            offset += rdlength
        return hostname, model_id
    except Exception:
        return None, None


# ── mDNS バックグラウンドリスナー ────────────────────────────────────────────

def start_mdns_listener(ip_list, mdns_results, mdns_models, done_event, timeout=MDNS_TIMEOUT):
    ip_set = set(ip_list)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bound = False
        try:
            sock.bind(('', 5353))
            bound = True
        except OSError:
            try: sock.bind(('', 0))
            except Exception: pass
        if bound:
            try:
                mreq = struct.pack('4sL', socket.inet_aton('224.0.0.251'), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception:
                pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.1)

        def _send(name, qu=False):
            qname  = _encode_dns_name(name)
            qclass = b'\x80\x01' if qu else b'\x00\x01'
            q = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c' + qclass
            try: sock.sendto(q, ('224.0.0.251', 5353))
            except Exception: pass

        _send('_services._dns-sd._udp.local')
        _send('_device-info._tcp.local')

        for ip in ip_list:
            rev   = '.'.join(reversed(ip.split('.')))
            qname = _encode_dns_name(f"{rev}.in-addr.arpa")
            q     = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x80\x01'
            try:
                sock.sendto(q, ('224.0.0.251', 5353))
                sock.sendto(q, (ip, 5353))
            except Exception:
                pass

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip in ip_set:
                    h, m = _extract_mdns_info(data, src_ip)
                    if h and src_ip not in mdns_results:
                        mdns_results[src_ip] = h
                    if m and src_ip not in mdns_models:
                        mdns_models[src_ip] = m
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()
    except Exception:
        pass
    finally:
        done_event.set()


# ── NetBIOS ─────────────────────────────────────────────────────────────────

def get_netbios_name(ip, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(
            b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01',
            (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) < 57: return None
        for i in range(data[56]):
            off  = 57 + i * 18
            if off + 18 > len(data): break
            name_type = data[off + 15]
            flags     = struct.unpack('>H', data[off + 16:off + 18])[0]
            if name_type == 0x00 and not (flags & 0x8000):
                name = data[off:off + 15].decode('ascii', errors='ignore').strip()
                if name: return name
        return None
    except Exception:
        return None


# ── デバイス解決（ホスト名 + model_id） ──────────────────────────────────────

def resolve_device(ip, mdns_results, mdns_models, done_event):
    try:
        h = socket.gethostbyaddr(ip)[0]
        if h and h != ip:
            return ip, h, mdns_models.get(ip)
    except Exception:
        pass
    name = get_netbios_name(ip)
    if name:
        return ip, name, mdns_models.get(ip)
    deadline = time.time() + MDNS_TIMEOUT
    while time.time() < deadline:
        if ip in mdns_results:
            return ip, mdns_results[ip], mdns_models.get(ip)
        if done_event.is_set(): break
        time.sleep(0.05)
    return ip, mdns_results.get(ip, '-'), mdns_models.get(ip)


# ── ベンダー解決 ─────────────────────────────────────────────────────────────

def load_vendor_lookup():
    mac = MacLookup()
    try:
        if not os.path.exists(BaseMacLookup.cache_path):
            print("[*] 初回起動のため MACベンダーDBをダウンロード中...")
            mac.update_vendors()
    except Exception as e:
        print(f"[!] ベンダーDB更新スキップ: {e}")
    return mac


def resolve_vendor(mac_address, mac_lookup):
    try:    return mac_lookup.lookup(mac_address)
    except: return "Unknown"


# ── モデル名表示 ─────────────────────────────────────────────────────────────

def build_model_str(mdns_model_id, ssdp_info):
    """mDNS Apple model / SSDP info を統合して表示用文字列を返す"""
    if ssdp_info:
        mfr   = ssdp_info.get('manufacturer', '')
        model = ssdp_info.get('modelName',    '')
        name  = ssdp_info.get('friendlyName', '')
        parts = [x for x in (mfr, model) if x]
        if parts:
            return ' '.join(parts)[:28]
        if name:
            return name[:28]
    if mdns_model_id:
        return APPLE_MODELS.get(mdns_model_id, mdns_model_id)
    return '-'


# ── メイン ──────────────────────────────────────────────────────────────────

def main():
    W = 110
    print("=" * W)
    print("                Wi-Fi 接続デバイス リアルタイム可視化ツール")
    print("=" * W)

    network_cidr, my_ip, iface = get_active_network()
    print(f"[*] インターフェース : {iface}")
    print(f"[*] 自分の IP       : {my_ip}")
    print(f"[*] スキャン対象    : {network_cidr}")
    print("-" * W)

    mac_lookup = load_vendor_lookup()

    print("[*] ARP スキャン中...")
    discovered = scan_network(network_cidr)
    if not discovered:
        print("[!] デバイス未発見。管理者権限で実行されているか確認してください。")
        return

    ip_list    = [d["ip"] for d in discovered]
    device_map = {d["ip"]: d for d in discovered}
    print(f"[*] {len(discovered)} 台発見。")

    # TTL 一括取得（OS推定に使用）
    print("[*] ICMP TTL 取得中...")
    ttl_map = get_ttl_batch(ip_list, timeout=2)

    # mDNS バックグラウンドリスナー起動
    mdns_results, mdns_models, done_event = {}, {}, threading.Event()
    threading.Thread(target=start_mdns_listener,
                     args=(ip_list, mdns_results, mdns_models, done_event, MDNS_TIMEOUT),
                     daemon=True).start()

    print("[*] ホスト名・機種情報・OS を解決中（取得できたものから随時表示）...\n")

    # テーブルヘッダー
    print("=" * W)
    print("                  アクティブなデバイス一覧（取得順）")
    print("=" * W)
    COL = f"{'IP':<20} | {'デバイス名':<22} | {'機種 / 製品名':<22} | {'推定OS':<16} | {'デバイス種別':<20} | MAC"
    print(COL)
    print("-" * W)

    # ── Phase 1: ホスト名解決 → 随時出力 ─────────────────────────────────
    resolved_hostnames = {}
    resolved_models    = {}

    with ThreadPoolExecutor(max_workers=30) as ex:
        fut_map = {ex.submit(resolve_device, ip, mdns_results, mdns_models, done_event): ip
                   for ip in ip_list}
        for fut in as_completed(fut_map):
            ip, hostname, model_id = fut.result()
            device    = device_map[ip]
            vendor    = resolve_vendor(device["mac"], mac_lookup)
            ttl       = ttl_map.get(ip)
            open_ports= []   # Phase2 で取得
            os_hint   = infer_os(ttl, vendor, hostname, open_ports)
            dev_type  = infer_device_type(ip, vendor, hostname, os_hint, open_ports)
            model_str = APPLE_MODELS.get(model_id, model_id) if model_id else '-'
            ip_disp   = f"{ip} (本体)" if ip == my_ip else ip

            print(f"{ip_disp:<20} | {hostname:<22} | {model_str:<22} | {os_hint:<16} | {dev_type:<20} | {device['mac']}")

            resolved_hostnames[ip] = hostname
            resolved_models[ip]    = model_id

    print("-" * W)
    host_count = sum(1 for h in resolved_hostnames.values() if h != '-')
    print(f"合計 {len(discovered)} 台 / ホスト名取得 {host_count} 台\n")

    # ── Phase 2: ポートスキャン + SSDP 詳細情報 ──────────────────────────
    print("[*] ポートスキャン + SSDP 詳細情報を収集中...")
    ssdp_info_map = collect_ssdp_info(set(ip_list), timeout=4)

    with ThreadPoolExecutor(max_workers=20) as ex:
        port_futures = {ex.submit(quick_port_scan, ip): ip for ip in ip_list}
        port_map     = {port_futures[f]: f.result() for f in as_completed(port_futures)}

    # ── 詳細情報ブロック ─────────────────────────────────────────────────
    has_detail = any(port_map.get(ip) or ssdp_info_map.get(ip) for ip in ip_list)
    if has_detail:
        print("\n" + "=" * W)
        print("  詳細情報（ポート / SSDP 機器情報）")
        print("=" * W)
        for d in discovered:
            ip       = d["ip"]
            hostname = resolved_hostnames.get(ip, '-')
            vendor   = resolve_vendor(d["mac"], mac_lookup)
            ports    = port_map.get(ip, [])
            ssdp     = ssdp_info_map.get(ip)
            model_id = resolved_models.get(ip)

            has_ports = bool(ports)
            has_ssdp  = bool(ssdp)
            has_model = bool(model_id)
            if not (has_ports or has_ssdp or has_model):
                continue

            ip_disp = f"{ip} (本体)" if ip == my_ip else ip
            print(f"\n  [{ip_disp}]  {hostname}")
            print(f"    MAC       : {d['mac']}  ← Wi-Fiアダプター製造元: {vendor}")

            if has_ssdp:
                print(f"    製品名    : {ssdp.get('friendlyName', '-')}")
                print(f"    モデル    : {ssdp.get('manufacturer','')  } {ssdp.get('modelName','')}")
                dtype = ssdp.get('deviceType', '')
                if dtype:
                    dtype = dtype.split(':')[-1] if ':' in dtype else dtype
                    print(f"    タイプ    : {dtype}")

            if has_model:
                print(f"    Apple機種 : {APPLE_MODELS.get(model_id, model_id)}")

            if has_ports:
                port_str = ', '.join(f"{p}({PORT_LABELS.get(p, '?')})" for p in sorted(ports))
                print(f"    開放ポート: {port_str}")

    # ── フッター: MAC アドレスについての補足 ────────────────────────────
    print("\n" + "─" * W)
    print("  【MACアドレスとメーカー表示について】")
    print("  MACアドレスは「PCブランド」ではなく「Wi-Fiアダプター（無線LANチップ）」の製造元を示します。")
    print("  例: ThinkPad (Lenovo) に搭載された JiangSu Fulian 製Wi-Fiカード → JiangSu Fulian と表示")
    print("  例: ASUS製ノートPCに Intel Wi-Fi チップ搭載              → Intel Corporate と表示")
    print("  PCの実際のブランドはSSDPや機種名列、またはデバイス名から判断してください。")
    print("─" * W)


if __name__ == "__main__":
    main()
