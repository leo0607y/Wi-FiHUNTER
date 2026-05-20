"""
Wi-Fi 接続デバイス リアルタイム可視化ツール

ホスト名解決の優先順位:
  1. 逆引き DNS
  2. NetBIOS (Windows)
  3. mDNS (Scapy AsyncSniffer によるドライバレベルキャプチャ)
     - ARP スキャン前から開始し、自発的アナウンスも取得
     - 逆引き PTR・サービス PTR・A レコードをすべて収集
     - _device-info / _apple-mobdev2 / _airplay 等多数のサービスを照会
     - クエリを3ラウンド送信（1.5秒間隔）
機種名取得:
  - Apple: mDNS _device-info TXT "model=XxxXX,N" → 人名に変換
  - その他: SSDP (UPnP) XML の friendlyName / modelName
"""

import os, time, socket, struct, threading, ipaddress, re, subprocess, ctypes
import urllib.request
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, BaseMacLookup
from concurrent.futures import ThreadPoolExecutor, as_completed

BaseMacLookup.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")

MDNS_TIMEOUT   = 9.0   # mDNS 収集の最大待機秒数
QUERY_ROUNDS   = 3     # mDNS クエリの再送回数
QUERY_INTERVAL = 1.8   # 再送間隔（秒）

# mDNS で照会するサービス一覧（Apple / Bonjour 系を網羅）
MDNS_SERVICES = [
    '_services._dns-sd._udp.local',   # 全サービス一覧（最重要トリガー）
    '_device-info._tcp.local',        # Apple 機種情報 (model=XXX)
    '_apple-mobdev2._tcp.local',      # iPhone/iPad ペアリング
    '_companion-link._tcp.local',     # Apple Watch 連携
    '_airplay._tcp.local',            # AirPlay
    '_raop._tcp.local',               # Remote Audio (AirPlay音声)
    '_sleep-proxy._udp.local',        # Bonjour Sleep Proxy
    '_smb._tcp.local',                # Samba / Windows 共有
    '_http._tcp.local',               # HTTP サービス
    '_ssh._tcp.local',                # SSH
    '_printer._tcp.local',            # プリンター
    '_homekit._tcp.local',            # HomeKit アクセサリ
    '_mediaremotetv._tcp.local',      # Apple TV リモート
    '_appletv-v2._tcp.local',         # Apple TV
    '_daap._tcp.local',               # iTunes 共有
    '_afpovertcp._tcp.local',         # AFP ファイル共有 (macOS)
    '_continuity._tcp.local',         # Continuity (iPhone↔Mac)
    '_rdlink._tcp.local',             # Apple Handoff
]

# Apple デバイス識別子 → 機種名
APPLE_MODELS = {
    'iPhone17,1':'iPhone 16 Pro',     'iPhone17,2':'iPhone 16 Pro Max',
    'iPhone17,3':'iPhone 16',         'iPhone17,4':'iPhone 16 Plus',
    'iPhone16,1':'iPhone 15 Pro',     'iPhone16,2':'iPhone 15 Pro Max',
    'iPhone15,4':'iPhone 15',         'iPhone15,5':'iPhone 15 Plus',
    'iPhone15,2':'iPhone 14 Pro',     'iPhone15,3':'iPhone 14 Pro Max',
    'iPhone14,7':'iPhone 14',         'iPhone14,8':'iPhone 14 Plus',
    'iPhone14,2':'iPhone 13 Pro',     'iPhone14,3':'iPhone 13 Pro Max',
    'iPhone14,4':'iPhone 13 mini',    'iPhone14,5':'iPhone 13',
    'iPhone13,1':'iPhone 12 mini',    'iPhone13,2':'iPhone 12',
    'iPhone13,3':'iPhone 12 Pro',     'iPhone13,4':'iPhone 12 Pro Max',
    'iPad14,1' :'iPad mini 6',        'iPad14,3' :'iPad Air 5',
    'iPad16,3' :'iPad Air 13 M2',     'iPad14,5' :'iPad Pro 11 M2',
    'iPad14,6' :'iPad Pro 12.9 M2',   'iPad13,18':'iPad 10th',
    'Mac14,2'  :'MacBook Air M2',     'Mac14,7'  :'MacBook Pro 13 M2',
    'Mac15,3'  :'MacBook Pro 14 M3',  'Mac15,6'  :'MacBook Pro 16 M3',
    'Mac14,3'  :'Mac mini M2',        'Mac15,13' :'MacBook Air 13 M3',
    'Watch7,1' :'Apple Watch S9 40',  'Watch7,2' :'Apple Watch S9 44',
    'Watch7,3' :'Apple Watch Ultra 2','Watch7,5' :'Apple Watch SE2',
    'AudioAccessory5,1':'HomePod 2',  'AudioAccessory6,1':'HomePod mini',
    'AppleTV14,1':'Apple TV 4K 3rd',
}

PORT_LABELS = {
    22:'SSH', 80:'HTTP', 139:'SMB', 443:'HTTPS', 445:'SMB',
    3389:'RDP', 5000:'UPnP', 8080:'HTTP-alt', 62078:'Apple-sync', 9100:'Printer',
}


# ─────────────────────────────────────────────────────────────────────────────
# 管理者権限チェック / 非管理者用スキャン
# ─────────────────────────────────────────────────────────────────────────────

def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        try: return os.geteuid() == 0
        except Exception: return False


def scan_network_noadmin(ip_range):
    """
    管理者権限不要の ARP スキャン。
    ping sweep で ARP キャッシュを埋め、arp -a で一覧取得。
    """
    network  = ipaddress.IPv4Network(ip_range, strict=False)
    host_set = {str(h) for h in network.hosts()}

    def ping_host(ip):
        try:
            subprocess.run(['ping', '-n', '1', '-w', '150', ip],
                           capture_output=True, timeout=0.8)
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=min(100, len(host_set))) as ex:
        list(ex.map(ping_host, sorted(host_set)))

    devices = []
    try:
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            m = re.match(r'\s+(\d+\.\d+\.\d+\.\d+)\s+([\da-fA-F-]{17})', line)
            if m:
                ip  = m.group(1)
                mac = m.group(2).replace('-', ':').lower()
                if ip in host_set and mac != 'ff:ff:ff:ff:ff:ff':
                    devices.append({'ip': ip, 'mac': mac})
    except Exception:
        pass

    # 自分自身が含まれない場合は追加
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        my_ip = s.getsockname()[0]
        s.close()
        if my_ip in host_set and not any(d['ip'] == my_ip for d in devices):
            import uuid
            raw = uuid.getnode()
            mac = ':'.join(f'{(raw >> (40 - 8*i)) & 0xff:02x}' for i in range(6))
            devices.append({'ip': my_ip, 'mac': mac})
    except Exception:
        pass

    devices.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
    return devices


def get_ttl_batch_noadmin(ip_list, timeout=1):
    """ping コマンドで TTL を並列取得（管理者権限不要）"""
    def get_ttl(ip):
        try:
            r = subprocess.run(
                ['ping', '-n', '1', '-w', str(int(timeout * 1000)), ip],
                capture_output=True, text=True, timeout=timeout + 1)
            m = re.search(r'TTL=(\d+)', r.stdout, re.I)
            if m:
                return ip, int(m.group(1))
        except Exception:
            pass
        return ip, None

    ttl_map = {}
    with ThreadPoolExecutor(max_workers=30) as ex:
        for ip, ttl in ex.map(get_ttl, ip_list):
            if ttl is not None:
                ttl_map[ip] = ttl
    return ttl_map


# ─────────────────────────────────────────────────────────────────────────────
# ネットワーク検出 / ARP スキャン
# ─────────────────────────────────────────────────────────────────────────────

def get_active_network():
    try:
        iface    = scapy.conf.iface
        local_ip = scapy.get_if_addr(str(iface))
        if local_ip and local_ip not in ('0.0.0.0', '127.0.0.1'):
            for e in scapy.conf.route.routes:
                if e[4] == local_ip and e[0] != 0 and e[1] != 0:
                    prefix   = bin(e[1] & 0xFFFFFFFF).count('1')
                    net_addr = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                    return str(net_addr), local_ip, str(iface)
    except Exception as err:
        print(f"[警告] インターフェース検出失敗: {err}")
    return "192.168.1.0/24", "192.168.1.x", "Default"


def scan_network(ip_range):
    pkt      = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip_range)
    answered = scapy.srp(pkt, timeout=3, retry=1, verbose=False)[0]
    devices  = [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]
    devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    return devices


# ─────────────────────────────────────────────────────────────────────────────
# ICMP TTL 取得（OS 推定用）
# ─────────────────────────────────────────────────────────────────────────────

def get_ttl_batch(ip_list, timeout=2):
    ttl_map = {}
    try:
        pkts     = [scapy.IP(dst=ip)/scapy.ICMP() for ip in ip_list]
        answered, _ = scapy.sr(pkts, timeout=timeout, verbose=False)
        for sent, recv in answered:
            ttl_map[sent.dst] = recv.ttl
    except Exception:
        pass
    return ttl_map


# ─────────────────────────────────────────────────────────────────────────────
# DNS ワイヤー形式ユーティリティ
# ─────────────────────────────────────────────────────────────────────────────

def _encode_dns_name(name: str) -> bytes:
    enc = b''
    for label in name.split('.'):
        if label:
            b = label.encode('utf-8')
            enc += bytes([len(b)]) + b
    return enc + b'\x00'


def _decode_dns_name(data: bytes, offset: int, depth=0):
    """圧縮ポインタ対応・UTF-8/latin-1 フォールバックつきデコード"""
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
            return '.'.join(labels), offset + 2
        offset += 1
        raw = data[offset:offset + length]
        try:
            labels.append(raw.decode('utf-8'))
        except UnicodeDecodeError:
            labels.append(raw.decode('latin-1', errors='replace'))
        offset += length
    return '.'.join(labels), offset


def _strip_local(name: str) -> str:
    """".local." や "._tcp.local" 等のサフィックスを除去してデバイス名を返す"""
    for suf in ('._device-info._tcp.local', '._companion-link._tcp.local',
                '._apple-mobdev2._tcp.local', '._airplay._tcp.local',
                '._raop._tcp.local', '._tcp.local', '._udp.local', '.local'):
        if name.lower().endswith(suf):
            return name[:-len(suf)].rstrip('.')
    return name.rstrip('.')


def _is_valid_hostname(name: str) -> bool:
    """mDNS から得た名前がデバイス名として有効かチェック"""
    if not name:
        return False
    # サービスタイプ名（_device-info 等）を除外
    if name.startswith('_'):
        return False
    # 極端に短い名前は除外
    if len(name) < 2:
        return False
    return True


def _extract_mdns_info(dns_bytes: bytes, src_ip: str):
    """
    mDNS パケット（生バイト）から (hostname, model_id) を抽出する。
    対応レコード: PTR(12) / A(1) / TXT(16)
    """
    try:
        if len(dns_bytes) < 12:
            return None, None
        # QR ビット確認（bit15 of flags: 1=response, 0=query）
        flags = int.from_bytes(dns_bytes[2:4], 'big')
        is_response = bool(flags & 0x8000)
        # クエリのみのパケットは無視（ただしアナウンスは QR=0 の場合もあるので警戒）

        qdcount = int.from_bytes(dns_bytes[4:6],  'big')
        ancount = int.from_bytes(dns_bytes[6:8],  'big')
        nscount = int.from_bytes(dns_bytes[8:10], 'big')
        arcount = int.from_bytes(dns_bytes[10:12],'big')
        total_rr = ancount + nscount + arcount
        if total_rr == 0:
            return None, None
        offset = 12
        for _ in range(qdcount):
            if offset >= len(dns_bytes):
                break
            _, offset = _decode_dns_name(dns_bytes, offset)
            offset += 4
        hostname = None
        model_id = None
        for _ in range(total_rr):
            if offset >= len(dns_bytes):
                break
            rec_name, offset = _decode_dns_name(dns_bytes, offset)
            if offset + 10 > len(dns_bytes):
                break
            rtype    = int.from_bytes(dns_bytes[offset:offset+2], 'big')
            offset  += 8                     # type + class + ttl
            rdlength = int.from_bytes(dns_bytes[offset:offset+2], 'big')
            offset  += 2
            if offset + rdlength > len(dns_bytes):
                break
            rdata    = dns_bytes[offset:offset + rdlength]

            if rtype == 12:   # PTR
                ptr_target, _ = _decode_dns_name(dns_bytes, offset)
                name = _strip_local(ptr_target)
                if _is_valid_hostname(name) and not hostname:
                    hostname = name

            elif rtype == 1 and rdlength == 4:   # A レコード
                try:
                    a_ip = socket.inet_ntoa(rdata)
                    if a_ip == src_ip:
                        name = _strip_local(rec_name)
                        if _is_valid_hostname(name) and not hostname:
                            hostname = name
                except Exception:
                    pass

            elif rtype == 16:   # TXT
                p = 0
                while p < len(rdata):
                    tl = rdata[p]; p += 1
                    if p + tl > len(rdata): break
                    txt = rdata[p:p+tl].decode('utf-8', errors='ignore')
                    p  += tl
                    if txt.lower().startswith('model='):
                        model_id = txt[6:].strip()

            elif rtype == 33 and rdlength >= 7:   # SRV
                # rec_name = "DeviceName._service._tcp.local" → インスタンス名を取り出す
                instance = _strip_local(rec_name)
                if _is_valid_hostname(instance) and not hostname:
                    hostname = instance

            offset += rdlength
        return hostname, model_id
    except Exception:
        return None, None


# ─────────────────────────────────────────────────────────────────────────────
# DHCP ホスト名スニッフ（スリープ中 iPhone のデバイス名取得）
# ─────────────────────────────────────────────────────────────────────────────

def collect_dhcp_hostnames(mac_to_ip, dhcp_results, done_event):
    """
    DHCP REQUEST/DISCOVER の option 12 (hostname) をスニッフしてデバイス名を収集。
    mac_to_ip は ARP スキャン完了後に更新される共有 dict（参照渡し）。
    iOS はプライベート MAC でも DHCP option 12 に本名を乗せる。
    """
    def on_dhcp(pkt):
        try:
            if not (pkt.haslayer(scapy.DHCP) and pkt.haslayer(scapy.Ether)):
                return
            mac = pkt[scapy.Ether].src.lower()
            for opt in pkt[scapy.DHCP].options:
                if not isinstance(opt, tuple) or opt[0] != 'hostname':
                    continue
                raw      = opt[1]
                hostname = (raw.decode('utf-8', errors='ignore')
                            if isinstance(raw, bytes) else str(raw)).strip()
                if hostname and _is_valid_hostname(hostname):
                    ip = mac_to_ip.get(mac)
                    if ip and ip not in dhcp_results:
                        dhcp_results[ip] = hostname
                break
        except Exception:
            pass

    try:
        sniffer = scapy.AsyncSniffer(
            filter='udp and (port 67 or port 68)',
            prn=on_dhcp,
            store=False)
        sniffer.start()
        done_event.wait()
        try: sniffer.stop()
        except: pass
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# mDNS 収集（Scapy AsyncSniffer + 多重クエリ送信）
#
# ip_list_ready: [None] → [ip_list] に設定されたら targeted queries を送信
# ARP スキャン前から sniffer を起動することで自発的アナウンスも捕捉する。
# ─────────────────────────────────────────────────────────────────────────────

def collect_mdns_with_sniff(ip_list_ready, mdns_results, mdns_models, done_event):
    """
    Scapy AsyncSniffer で UDP 5353 をドライバレベルでキャプチャ。
    IP フィルターなし：ARP スキャン前の自発的アナウンスも収集する。
    ip_list_ready[0] に ip_list が設定されたら targeted queries を送信する。
    """
    def on_packet(pkt):
        try:
            if not (pkt.haslayer(scapy.IP) and pkt.haslayer(scapy.UDP)):
                return
            src_ip = pkt[scapy.IP].src
            dns_bytes = bytes(pkt[scapy.UDP].payload)
            h, m = _extract_mdns_info(dns_bytes, src_ip)
            if h and src_ip not in mdns_results:
                mdns_results[src_ip] = h
            if m and src_ip not in mdns_models:
                mdns_models[src_ip] = m
        except Exception:
            pass

    # ── Scapy AsyncSniffer 起動 ────────────────────────────────────────────
    sniffer = None
    try:
        sniffer = scapy.AsyncSniffer(filter="udp port 5353", prn=on_packet, store=False)
        sniffer.start()
    except Exception as e:
        print(f"[警告] mDNS スニッファー起動失敗 ({e})。raw socket にフォールバック。")
        # ip_list が来るまで待機
        wait_start = time.time()
        while time.time() - wait_start < 60:
            if ip_list_ready[0] is not None:
                break
            time.sleep(0.1)
        ip_list = ip_list_ready[0] or []
        _collect_mdns_raw_socket(ip_list, mdns_results, mdns_models)
        done_event.set()
        return

    # ── ip_list が届くまで待機（ARP スキャン完了まで）────────────────────
    wait_start = time.time()
    while time.time() - wait_start < 60:
        if ip_list_ready[0] is not None:
            break
        time.sleep(0.1)

    ip_list = ip_list_ready[0] or []

    # ── クエリ送信（複数ラウンド） ─────────────────────────────────────────
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.setsockopt(socket.SOL_SOCKET,  socket.SO_REUSEADDR, 1)

        def sq(name: str, qu=False):
            qname  = _encode_dns_name(name)
            qclass = b'\x80\x01' if qu else b'\x00\x01'
            q = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 + qname + b'\x00\x0c' + qclass)
            try: sock.sendto(q, ('224.0.0.251', 5353))
            except: pass

        def send_all():
            # サービスディスカバリ・モデル情報トリガー
            for svc in MDNS_SERVICES:
                sq(svc)
            # 各 IP の逆引き PTR（QU=False: マルチキャスト応答させてスニッファーで拾う）
            for ip in ip_list:
                rev   = '.'.join(reversed(ip.split('.')))
                qname = _encode_dns_name(f"{rev}.in-addr.arpa")
                query = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                         + qname + b'\x00\x0c\x00\x01')
                try:
                    sock.sendto(query, ('224.0.0.251', 5353))  # multicast のみ
                    sock.sendto(query, (ip, 5353))              # unicast (ポート5353から送信)
                except: pass

        for round_no in range(QUERY_ROUNDS):
            send_all()
            time.sleep(QUERY_INTERVAL)

        sock.close()
    except Exception:
        pass

    # 残り時間まで待機
    elapsed  = QUERY_ROUNDS * QUERY_INTERVAL
    leftover = MDNS_TIMEOUT - elapsed
    if leftover > 0:
        time.sleep(leftover)

    try:
        sniffer.stop()
    except Exception:
        pass

    done_event.set()


def _collect_mdns_raw_socket(ip_list, mdns_results, mdns_models, timeout=MDNS_TIMEOUT):
    """AsyncSniffer が使えない場合の raw socket フォールバック"""
    ip_set = set(ip_list)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('', 5353))
            mreq = struct.pack('4sL', socket.inet_aton('224.0.0.251'), socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        except OSError:
            try: sock.bind(('', 0))
            except: pass
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.1)
        for svc in MDNS_SERVICES:
            qname = _encode_dns_name(svc)
            q = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x00\x01'
            try: sock.sendto(q, ('224.0.0.251', 5353))
            except: pass
        for ip in ip_list:
            rev   = '.'.join(reversed(ip.split('.')))
            qname = _encode_dns_name(f"{rev}.in-addr.arpa")
            q     = b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x80\x01'
            try:
                sock.sendto(q, ('224.0.0.251', 5353))
                sock.sendto(q, (ip, 5353))
            except: pass
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip in ip_set:
                    h, m = _extract_mdns_info(data, src_ip)
                    if h and src_ip not in mdns_results: mdns_results[src_ip] = h
                    if m and src_ip not in mdns_models:  mdns_models[src_ip]  = m
            except socket.timeout:
                continue
            except: break
        sock.close()
    except Exception:
        pass


# ─────────────────────────────────────────────────────────────────────────────
# LLMNR (Link-Local Multicast Name Resolution)
# ─────────────────────────────────────────────────────────────────────────────

def get_llmnr_name(ip, timeout=1):
    """LLMNR PTR クエリでホスト名取得（NetBIOS が無効な Windows/Linux デバイス向け）"""
    try:
        rev   = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
        qname = _encode_dns_name(rev)
        query = (b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                 + qname + b'\x00\x0c\x00\x01')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        try: sock.sendto(query, ('224.0.0.252', 5355))
        except: pass
        try: sock.sendto(query, (ip, 5355))
        except: pass
        try:
            while True:
                data, (src, _) = sock.recvfrom(1024)
                if src != ip or len(data) < 12:
                    continue
                ancount = int.from_bytes(data[6:8], 'big')
                if ancount == 0:
                    break
                offset = 12
                _, offset = _decode_dns_name(data, offset)
                offset += 4
                for _ in range(ancount):
                    if offset >= len(data): break
                    _, offset = _decode_dns_name(data, offset)
                    if offset + 10 > len(data): break
                    rtype  = int.from_bytes(data[offset:offset+2], 'big')
                    offset += 8
                    rdlen  = int.from_bytes(data[offset:offset+2], 'big')
                    offset += 2
                    if rtype == 12:
                        name, _ = _decode_dns_name(data, offset)
                        name = _strip_local(name)
                        if _is_valid_hostname(name):
                            sock.close()
                            return name
                    offset += rdlen
                break
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass
    return None


def get_http_title(ip, timeout=1.2):
    """HTTP ポート 80/8080 の HTML タイトルまたは Server ヘッダーからデバイス名を取得"""
    for port in (80, 8080):
        try:
            url = f"http://{ip}:{port}/"
            req = urllib.request.Request(url, headers={'User-Agent': 'Wi-FiHUNTER/1.0'})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                server  = r.headers.get('Server', '')
                content = r.read(2048).decode('utf-8', errors='ignore')
            m = re.search(r'<title[^>]*>(.*?)</title>', content, re.I | re.S)
            if m:
                title = re.sub(r'\s+', ' ', m.group(1)).strip()[:30]
                bad   = ('403', '404', 'error', 'unauthorized', 'access denied', 'login', 'redirect')
                if title and not any(b in title.lower() for b in bad):
                    return title
            if server:
                s = server.split('/')[0].strip()[:30]
                if len(s) > 2:
                    return s
        except Exception:
            continue
    return None


# ─────────────────────────────────────────────────────────────────────────────
# NetBIOS
# ─────────────────────────────────────────────────────────────────────────────

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
            off = 57 + i * 18
            if off + 18 > len(data): break
            if data[off+15] == 0x00 and not (struct.unpack('>H', data[off+16:off+18])[0] & 0x8000):
                name = data[off:off+15].decode('ascii', errors='ignore').strip()
                if name: return name
        return None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# デバイス解決（DNS → NetBIOS → mDNS スニッフ結果を待機）
# ─────────────────────────────────────────────────────────────────────────────

def resolve_device(ip, mdns_results, mdns_models, done_event, ssdp_early=None, dhcp_results=None):
    # 1. 逆引き DNS
    try:
        h = socket.gethostbyaddr(ip)[0]
        if h and h != ip:
            return ip, h, mdns_models.get(ip)
    except Exception:
        pass
    # 2. NetBIOS
    name = get_netbios_name(ip)
    if name:
        return ip, name, mdns_models.get(ip)
    # 3. mDNS / DHCP 結果を並行待機（DHCP はリース更新タイミングで届く）
    deadline = time.time() + MDNS_TIMEOUT
    while time.time() < deadline:
        if ip in mdns_results:
            return ip, mdns_results[ip], mdns_models.get(ip)
        if dhcp_results and ip in dhcp_results:
            return ip, dhcp_results[ip], mdns_models.get(ip)
        if done_event.is_set():
            break
        time.sleep(0.05)
    if dhcp_results and ip in dhcp_results:
        return ip, dhcp_results[ip], mdns_models.get(ip)
    # 4. LLMNR
    name = get_llmnr_name(ip)
    if name:
        return ip, name, mdns_models.get(ip)
    # 5. SSDP friendlyName（バックグラウンド収集済み分）
    if ssdp_early is not None:
        ssdp = ssdp_early.get(ip)
        if ssdp:
            fname = ssdp.get('friendlyName') or ssdp.get('modelName')
            if fname:
                return ip, fname[:24].strip(), mdns_models.get(ip)
    # 6. HTTP タイトル / Server ヘッダー
    name = get_http_title(ip)
    if name:
        return ip, name, mdns_models.get(ip)
    return ip, mdns_results.get(ip, '-'), mdns_models.get(ip)


# ─────────────────────────────────────────────────────────────────────────────
# SSDP (UPnP) 機器情報収集
# ─────────────────────────────────────────────────────────────────────────────

def collect_ssdp_info(ip_set, timeout=4):
    locations = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.settimeout(0.2)
        msg = ('M-SEARCH * HTTP/1.1\r\n'
               'HOST: 239.255.255.250:1900\r\n'
               'MAN: "ssdp:discover"\r\n'
               'MX: 2\r\nST: ssdp:all\r\n\r\n').encode()
        # マルチキャスト + ユニキャスト両方に送信
        try: sock.sendto(msg, ('239.255.255.250', 1900))
        except: pass
        for ip in ip_set:
            try: sock.sendto(msg, (ip, 1900))
            except: pass
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip in ip_set and src_ip not in locations:
                    for line in data.decode('utf-8', errors='replace').split('\r\n'):
                        if line.lower().startswith('location:'):
                            locations[src_ip] = line.split(':', 1)[1].strip()
                            break
            except socket.timeout: continue
            except: break
        sock.close()
    except Exception:
        pass
    ssdp_info = {}
    with ThreadPoolExecutor(max_workers=10) as ex:
        fut_map = {ex.submit(_fetch_ssdp_xml, url): ip for ip, url in locations.items()}
        for fut in as_completed(fut_map):
            ip   = fut_map[fut]
            info = fut.result()
            if info: ssdp_info[ip] = info
    return ssdp_info


def _ssdp_worker(ip_list, result_dict, timeout=7):
    """SSDP 収集をバックグラウンドで実行し result_dict に格納（Phase1 の hostname fallback 用）"""
    result = collect_ssdp_info(set(ip_list), timeout=timeout)
    result_dict.update(result)


def _fetch_ssdp_xml(url, timeout=3):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Wi-FiHUNTER/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            xml = r.read().decode('utf-8', errors='replace')
        info = {}
        for tag in ('friendlyName', 'modelName', 'modelNumber', 'manufacturer', 'deviceType'):
            m = re.search(fr'<{tag}[^>]*>\s*(.*?)\s*</{tag}>', xml, re.I | re.S)
            if m: info[tag] = m.group(1).strip()[:50]
        return info or None
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# ポートスキャン / OS・デバイス種別推定
# ─────────────────────────────────────────────────────────────────────────────

def scan_apple_sync(ip_list, timeout=0.4):
    """ポート 62078 (iTunes Wi-Fi Sync) を並列チェックして iOS デバイスの IP 集合を返す"""
    result = set()
    def check(ip):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, 62078)) == 0:
                s.close()
                return ip
            s.close()
        except: pass
        return None
    with ThreadPoolExecutor(max_workers=20) as ex:
        for r in ex.map(check, ip_list):
            if r: result.add(r)
    return result


def quick_port_scan(ip, ports=(22, 80, 139, 443, 445, 3389, 5000, 62078, 9100), timeout=0.35):
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, p)) == 0: open_ports.append(p)
            s.close()
        except: pass
    return open_ports


def infer_os(ttl, vendor, hostname, ports, model_id=None):
    v, h, p = (vendor or '').lower(), (hostname or '').lower(), set(ports or [])
    mid = (model_id or '').lower()

    # model_id による高精度判定（mDNS _device-info から取得した場合）
    if mid.startswith('iphone') or mid.startswith('ipod'):  return 'iOS'
    if mid.startswith('ipad'):                              return 'iPadOS'
    if mid.startswith('watch'):                             return 'watchOS'
    if mid.startswith('appletv'):                           return 'tvOS'
    if mid.startswith('audioaccessory'):                    return 'HomePod OS'
    if mid.startswith('mac'):                               return 'macOS'

    # ホスト名 + ポートによる判定
    # ポート 62078 は iOS/iPadOS 専用（Apple sync）。ランダム MAC でも確実に iOS と判定
    if 62078 in p: return 'iOS'

    if 'apple' in v:
        if any(x in h for x in ('iphone','ipod')): return 'iOS'
        if 'ipad' in h:                             return 'iPadOS'
        return 'macOS / iOS'

    if {445,3389}&p or h.startswith(('desktop-','laptop-')): return 'Windows'
    if 22 in p: return 'Linux'
    if ttl:
        if ttl >= 110: return 'Windows'
        if ttl >= 50:
            if 'samsung' in v: return 'Android'
            return 'Linux / macOS'
    if 'samsung' in v: return 'Android (推定)'
    if 'raspberr' in v: return 'Linux'
    return '不明'


def infer_device_type(ip, vendor, hostname, os_hint, ports, model_id=None):
    v, h, p = (vendor or '').lower(), (hostname or '').lower(), set(ports or [])
    mid = (model_id or '').lower()

    # model_id から正確なデバイス種別を判定
    if mid.startswith('iphone') or mid.startswith('ipod'): return 'iPhone'
    if mid.startswith('ipad'):                             return 'iPad'
    if mid.startswith('watch'):                            return 'Apple Watch'
    if mid.startswith('appletv'):                          return 'Apple TV'
    if mid.startswith('audioaccessory'):                   return 'HomePod'
    if mid.startswith('mac'):                              return 'Mac'

    # ポート 62078 はランダム MAC でも iOS/iPadOS を確定できる
    if 62078 in p: return 'iPhone / iPad'

    if any(x in v for x in ('asus','buffalo','nec','tp-link','netgear','cisco','yamaha')):
        if ip.endswith('.1') or any(x in h for x in ('router','gateway','rt-','ap')):
            return 'ルーター / AP'
    if 'raspberr' in v or 'raspberrypi' in h: return 'Raspberry Pi'
    if 'apple' in v:
        for k,r in (('iphone','iPhone'),('ipad','iPad'),('watch','Apple Watch'),
                    ('appletv','Apple TV'),('homepod','HomePod'),('mac','Mac')):
            if k in h: return r
        return 'Apple デバイス'
    if 3389 in p or h.startswith('desktop-'): return 'Windows デスクトップ'
    if h.startswith('laptop-') or 'laptop' in h: return 'Windows ノートPC'
    if 445 in p and os_hint == 'Windows': return 'Windows PC'
    if 9100 in p: return 'プリンター'
    if 22 in p: return 'Linux サーバー'
    if 'samsung' in v: return 'Samsung (スマホ/TV)'
    if 'sony'    in v: return 'Sony デバイス'
    if any(x in v for x in ('ampak','azurewave','espressif')): return 'IoT / 組み込み'
    if 'buffalo' in v: return 'NAS / 周辺機器'
    return '不明'


# ─────────────────────────────────────────────────────────────────────────────
# ベンダー解決
# ─────────────────────────────────────────────────────────────────────────────

def load_vendor_lookup():
    mac = MacLookup()
    try:
        if not os.path.exists(BaseMacLookup.cache_path):
            print("[*] MACベンダーDB をダウンロード中...")
            mac.update_vendors()
    except Exception as e:
        print(f"[!] ベンダーDB 更新スキップ: {e}")
    return mac


def resolve_vendor(mac_addr, mac_lookup):
    try:    return mac_lookup.lookup(mac_addr)
    except: return "Unknown"


# ─────────────────────────────────────────────────────────────────────────────
# メイン
# ─────────────────────────────────────────────────────────────────────────────

def main():
    W = 108
    print("=" * W)
    print("               Wi-Fi 接続デバイス リアルタイム可視化ツール")
    print("=" * W)

    network_cidr, my_ip, iface = get_active_network()
    admin = _is_admin()
    print(f"[*] インターフェース : {iface}")
    print(f"[*] 自分の IP       : {my_ip}")
    print(f"[*] スキャン対象    : {network_cidr}")
    print(f"[*] 実行モード      : {'管理者（高精度）' if admin else '一般ユーザー（ping モード）'}")
    print("-" * W)

    mac_lookup = load_vendor_lookup()

    # ── mDNS + DHCP スニッファーを ARP スキャン前に開始 ─────────────────────
    mdns_results, mdns_models, done_event = {}, {}, threading.Event()
    ip_list_ready = [None]
    mac_to_ip     = {}   # ARP 完了後に更新（DHCP スニッファーが参照）
    dhcp_results  = {}

    mdns_thread = threading.Thread(
        target=collect_mdns_with_sniff,
        args=(ip_list_ready, mdns_results, mdns_models, done_event),
        daemon=True)
    mdns_thread.start()

    if admin:
        dhcp_thread = threading.Thread(
            target=collect_dhcp_hostnames,
            args=(mac_to_ip, dhcp_results, done_event),
            daemon=True)
        dhcp_thread.start()

    time.sleep(0.3)   # スニッファー安定待ち

    print("[*] ARP スキャン中...")
    discovered = scan_network(network_cidr) if admin else scan_network_noadmin(network_cidr)
    if not discovered:
        print("[!] デバイス未発見。")
        done_event.set()
        return

    ip_list    = [d["ip"] for d in discovered]
    device_map = {d["ip"]: d for d in discovered}
    print(f"[*] {len(discovered)} 台発見。")

    # ARP 結果を共有 dict に反映（DHCP スニッファーが MAC→IP 解決に使用）
    mac_to_ip.update({d["mac"].lower(): d["ip"] for d in discovered})

    # ARP 結果を渡して targeted mDNS queries を開始させる
    ip_list_ready[0] = ip_list

    # SSDP をバックグラウンドで即開始（Phase1 hostname fallback に間に合わせる）
    ssdp_early = {}
    ssdp_bg_thread = threading.Thread(
        target=_ssdp_worker, args=(ip_list, ssdp_early, 7), daemon=True)
    ssdp_bg_thread.start()

    print("[*] TTL 収集中（OS推定用）/ ポート 62078 (iOS判定) チェック中...")
    ttl_getter = get_ttl_batch if admin else get_ttl_batch_noadmin
    with ThreadPoolExecutor(max_workers=2) as ex:
        ttl_fut        = ex.submit(ttl_getter, ip_list)
        apple_sync_fut = ex.submit(scan_apple_sync, ip_list)
    ttl_map        = ttl_fut.result()
    apple_sync_set = apple_sync_fut.result()

    print(f"[*] ホスト名・OS・機種情報 を解決中（随時表示）...\n")

    # ── Phase 1: 進行テーブル ──────────────────────────────────────────────
    H = (f"{'IP':<20} | {'デバイス名':<24} | {'推定OS':<14} | "
         f"{'デバイス種別':<22} | MAC")
    print("=" * W)
    print("                  接続デバイス一覧（解決できたものから順に表示）")
    print("=" * W)
    print(H)
    print("-" * W)

    resolved_all = {}   # ip -> {hostname, model_id, ports}
    with ThreadPoolExecutor(max_workers=30) as ex:
        fut_map = {ex.submit(resolve_device, ip, mdns_results, mdns_models, done_event, ssdp_early, dhcp_results): ip
                   for ip in ip_list}
        for fut in as_completed(fut_map):
            ip, hostname, model_id = fut.result()
            device      = device_map[ip]
            vendor      = resolve_vendor(device["mac"], mac_lookup)
            ttl         = ttl_map.get(ip)
            ports_hint  = [62078] if ip in apple_sync_set else []
            os_hint     = infer_os(ttl, vendor, hostname, ports_hint, model_id)
            dev_type    = infer_device_type(ip, vendor, hostname, os_hint, ports_hint, model_id)
            ip_disp  = f"{ip} (本体)" if ip == my_ip else ip
            print(f"{ip_disp:<20} | {hostname:<24} | {os_hint:<14} | {dev_type:<22} | {device['mac']}")
            resolved_all[ip] = {'hostname': hostname, 'model_id': model_id}

    host_ok = sum(1 for v in resolved_all.values() if v['hostname'] != '-')
    mdns_ok = sum(1 for ip in ip_list if ip in mdns_results)
    model_ok= sum(1 for ip in ip_list if ip in mdns_models)
    print("-" * W)
    print(f"合計 {len(discovered)} 台  /  ホスト名取得: {host_ok} 台  /  "
          f"mDNS 解決: {mdns_ok} 台  /  Apple機種: {model_ok} 台\n")

    # ── Phase 2: ポートスキャン + SSDP ────────────────────────────────────
    print("[*] ポートスキャン + SSDP 詳細情報 を収集中...")
    ssdp_bg_thread.join(timeout=2)   # バックグラウンド SSDP の完了を最大2秒待機
    ssdp_map = ssdp_early

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures  = [(ex.submit(quick_port_scan, ip), ip) for ip in ip_list]
        port_map = {ip: fut.result() for fut, ip in futures}

    # 機種名を統合（SSDP > Apple mDNS > '-'）
    def build_model(ip):
        ssdp = ssdp_map.get(ip)
        if ssdp:
            parts = [x for x in (ssdp.get('manufacturer',''), ssdp.get('modelName','')) if x]
            return ' '.join(parts)[:30] if parts else ssdp.get('friendlyName','-')[:30]
        mid = resolved_all.get(ip, {}).get('model_id')
        if mid:
            return APPLE_MODELS.get(mid, mid)
        return '-'

    # ── 詳細情報テーブル ──────────────────────────────────────────────────
    print("\n" + "=" * W)
    print("  詳細情報（機種名 / 開放ポート / SSDP 製品情報）")
    print("=" * W)
    detail_header = f"{'IP':<20} | {'機種名 / 製品名':<30} | {'開放ポート':<30} | メーカー(WiFiアダプター)"
    print(detail_header)
    print("-" * W)
    for d in discovered:
        ip       = d["ip"]
        vendor   = resolve_vendor(d["mac"], mac_lookup)
        model    = build_model(ip)
        ports    = port_map.get(ip, [])
        port_str = ', '.join(f"{p}({PORT_LABELS.get(p,'?')})" for p in sorted(ports)) or '-'
        ip_disp  = f"{ip} (本体)" if ip == my_ip else ip
        print(f"{ip_disp:<20} | {model:<30} | {port_str:<30} | {vendor}")

    print("-" * W)


if __name__ == "__main__":
    main()
