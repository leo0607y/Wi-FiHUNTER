import os
import math
import time
import socket
import struct
import threading
import ipaddress
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, BaseMacLookup
from concurrent.futures import ThreadPoolExecutor, as_completed

BaseMacLookup.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")

MDNS_TIMEOUT = 5.0

# Apple デバイス識別子 → 機種名マッピング
APPLE_MODELS = {
    # iPhone 16
    'iPhone17,1': 'iPhone 16 Pro', 'iPhone17,2': 'iPhone 16 Pro Max',
    'iPhone17,3': 'iPhone 16',     'iPhone17,4': 'iPhone 16 Plus',
    # iPhone 15
    'iPhone16,1': 'iPhone 15 Pro', 'iPhone16,2': 'iPhone 15 Pro Max',
    'iPhone15,4': 'iPhone 15',     'iPhone15,5': 'iPhone 15 Plus',
    # iPhone 14
    'iPhone15,2': 'iPhone 14 Pro', 'iPhone15,3': 'iPhone 14 Pro Max',
    'iPhone14,7': 'iPhone 14',     'iPhone14,8': 'iPhone 14 Plus',
    # iPhone 13
    'iPhone14,2': 'iPhone 13 Pro', 'iPhone14,3': 'iPhone 13 Pro Max',
    'iPhone14,4': 'iPhone 13 mini','iPhone14,5': 'iPhone 13',
    # iPhone 12
    'iPhone13,1': 'iPhone 12 mini','iPhone13,2': 'iPhone 12',
    'iPhone13,3': 'iPhone 12 Pro', 'iPhone13,4': 'iPhone 12 Pro Max',
    # iPad
    'iPad13,18': 'iPad (10th gen)','iPad13,19': 'iPad (10th gen)',
    'iPad14,1':  'iPad mini 6',    'iPad14,2':  'iPad mini 6',
    'iPad14,3':  'iPad Air 5',     'iPad14,4':  'iPad Air 5',
    'iPad16,3':  'iPad Air 13 M2', 'iPad16,4':  'iPad Air 13 M2',
    'iPad13,4':  'iPad Pro 11 M1', 'iPad13,8':  'iPad Pro 12.9 M1',
    'iPad14,5':  'iPad Pro 11 M2', 'iPad14,6':  'iPad Pro 12.9 M2',
    # Mac
    'Mac14,2':   'MacBook Air M2', 'Mac14,7':   'MacBook Pro 13 M2',
    'Mac15,3':   'MacBook Pro 14 M3','Mac15,6':  'MacBook Pro 16 M3 Pro',
    'Mac15,7':   'MacBook Pro 16 M3 Max',
    'Mac14,3':   'Mac mini M2',    'Mac14,12':  'Mac mini M2 Pro',
    # Apple Watch
    'Watch7,1':  'Apple Watch S9 40mm','Watch7,2':'Apple Watch S9 44mm',
    'Watch7,3':  'Apple Watch Ultra 2','Watch7,5': 'Apple Watch SE2',
    # HomePod / Apple TV
    'AudioAccessory5,1': 'HomePod 2',
    'AudioAccessory6,1': 'HomePod mini',
    'AppleTV14,1': 'Apple TV 4K 3rd',
}


def friendly_model(model_id):
    """Apple モデル識別子を人が読める機種名に変換する"""
    if not model_id:
        return '-'
    return APPLE_MODELS.get(model_id, model_id)


# ── ネットワーク検出 ─────────────────────────────────────────────────────────

def get_active_network():
    try:
        iface    = scapy.conf.iface
        local_ip = scapy.get_if_addr(str(iface))
        if local_ip and local_ip not in ('0.0.0.0', '127.0.0.1'):
            for entry in scapy.conf.route.routes:
                network, netmask, _, interface, address = (
                    entry[0], entry[1], entry[2], entry[3], entry[4]
                )
                if address == local_ip and network != 0 and netmask != 0:
                    prefix   = bin(netmask & 0xFFFFFFFF).count('1')
                    net_addr = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                    return str(net_addr), local_ip, str(iface)
    except Exception as e:
        print(f"[警告] アクティブインターフェースの自動取得に失敗しました: {e}")
    return "192.168.1.0/24", "192.168.1.x", "Default"


# ── ARP スキャン ─────────────────────────────────────────────────────────────

def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast   = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    answered    = scapy.srp(broadcast / arp_request, timeout=3, retry=1, verbose=False)[0]
    devices     = [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]
    devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    return devices


# ── DNS ワイヤー形式ユーティリティ ────────────────────────────────────────────

def _encode_dns_name(name):
    encoded = b''
    for label in name.split('.'):
        if label:
            encoded += bytes([len(label)]) + label.encode('utf-8')
    return encoded + b'\x00'


def _decode_dns_name(data, offset, depth=0):
    """
    DNS ワイヤー形式のドメイン名をデコード。
    各ラベルは UTF-8 として扱うことで日本語・絵文字等の非ASCII文字に対応する。
    """
    labels = []
    if depth > 10:
        return '', offset
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # 圧縮ポインタ
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            sub, _ = _decode_dns_name(data, ptr, depth + 1)
            labels.append(sub)
            offset += 2
            return '.'.join(labels), offset
        offset += 1
        raw = data[offset:offset + length]
        # UTF-8 で試みてから latin-1 にフォールバック
        try:
            labels.append(raw.decode('utf-8'))
        except UnicodeDecodeError:
            labels.append(raw.decode('latin-1', errors='replace'))
        offset += length
    return '.'.join(labels), offset


def _extract_mdns_info(data, src_ip):
    """
    mDNS パケットを全セクション走査し (hostname, model_id) を返す。

    対応レコードタイプ:
      PTR (12): in-addr.arpa 逆引き → hostname
      A   (1):  A レコードが src_ip を指す → レコード名 = hostname
      TXT (16): model= フィールド → model_id
    """
    try:
        if len(data) < 12:
            return None, None

        qdcount = int.from_bytes(data[4:6],  'big')
        ancount = int.from_bytes(data[6:8],  'big')
        nscount = int.from_bytes(data[8:10], 'big')
        arcount = int.from_bytes(data[10:12],'big')
        total   = ancount + nscount + arcount

        if total == 0:
            return None, None

        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_dns_name(data, offset)
            offset += 4

        hostname = None
        model_id = None

        for _ in range(total):
            if offset >= len(data):
                break

            rec_name, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break

            rtype    = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 8                                              # type+class+ttl
            rdlength = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 2
            rdata    = data[offset:offset + rdlength]

            # ── PTR ──────────────────────────────────────────────────────────
            if rtype == 12:
                ptr_target, _ = _decode_dns_name(data, offset)
                if 'in-addr.arpa' in rec_name:
                    # 逆引き PTR → そのまま hostname
                    name = ptr_target.removesuffix('.local').rstrip('.')
                    if name and not hostname:
                        hostname = name
                elif '_device-info' in rec_name or '_tcp' in rec_name:
                    # サービス PTR → インスタンス名の先頭部分が device name
                    for suffix in ('._device-info._tcp.local', '._tcp.local', '.local'):
                        if ptr_target.endswith(suffix):
                            name = ptr_target[:-len(suffix)].rstrip('.')
                            if name and not hostname:
                                hostname = name
                            break

            # ── A レコード ────────────────────────────────────────────────────
            elif rtype == 1 and rdlength == 4:
                record_ip = socket.inet_ntoa(rdata)
                if record_ip == src_ip:
                    # このパケット送信元 IP を指す A レコード → 名前がホスト名
                    name = rec_name.removesuffix('.local').rstrip('.')
                    # サービス名（._tcp 等）を除外
                    if name and '._' not in name and not hostname:
                        hostname = name

            # ── TXT ──────────────────────────────────────────────────────────
            elif rtype == 16:
                txt_off = 0
                while txt_off < len(rdata):
                    txt_len = rdata[txt_off]
                    txt_off += 1
                    if txt_off + txt_len > len(rdata):
                        break
                    try:
                        txt_str = rdata[txt_off:txt_off + txt_len].decode('utf-8', errors='ignore')
                    except Exception:
                        txt_str = ''
                    txt_off += txt_len
                    if txt_str.lower().startswith('model='):
                        model_id = txt_str[6:].strip()

            offset += rdlength

        return hostname, model_id
    except Exception:
        return None, None


# ── mDNS バックグラウンドリスナー ────────────────────────────────────────────

def start_mdns_listener(ip_list, mdns_results, mdns_models, done_event, timeout=MDNS_TIMEOUT):
    """
    バックグラウンドスレッドで mDNS を収集する。

    1. ポート 5353 へバインドし、マルチキャストグループ (224.0.0.251) に参加
       → iPhone 等がマルチキャストで返した応答をすべて受信できる
    2. サービスディスカバリトリガー + device-info クエリで iPhone/Mac に自己紹介を促す
    3. 各 IP の逆引き PTR クエリをマルチキャスト + ユニキャスト両方に送信
    4. A レコード・TXT レコードも解析してホスト名と機種情報を収集
    """
    ip_set = set(ip_list)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # ポート 5353 にバインド（マルチキャスト応答の受信に必要）
        bound_to_5353 = False
        try:
            sock.bind(('', 5353))
            bound_to_5353 = True
        except OSError:
            try:
                sock.bind(('', 0))  # 占有されていたら任意ポート
            except Exception:
                pass

        # マルチキャストグループ 224.0.0.251 に参加
        if bound_to_5353:
            try:
                mreq = struct.pack('4sL', socket.inet_aton('224.0.0.251'), socket.INADDR_ANY)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            except Exception:
                pass

        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.1)

        def send_mdns_query(name, qtype=0x000c, qu=False):
            qname  = _encode_dns_name(name)
            qclass = b'\x80\x01' if qu else b'\x00\x01'  # QU bit or IN class
            query  = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                      + qname
                      + qtype.to_bytes(2, 'big')
                      + qclass)
            try:
                sock.sendto(query, ('224.0.0.251', 5353))
            except Exception:
                pass

        # ① サービスディスカバリトリガー（Apple デバイスの自己紹介を促す）
        send_mdns_query('_services._dns-sd._udp.local')
        send_mdns_query('_device-info._tcp.local')

        # ② 各 IP の逆引き PTR クエリ（マルチキャスト + ユニキャスト）
        for ip in ip_list:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            qname  = _encode_dns_name(f"{reversed_ip}.in-addr.arpa")
            # QU bit 付き（ユニキャスト応答を要求）
            query  = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                      + qname + b'\x00\x0c\x80\x01')
            try:
                sock.sendto(query, ('224.0.0.251', 5353))  # multicast
                sock.sendto(query, (ip, 5353))              # unicast fallback
            except Exception:
                pass

        # 応答を timeout 秒間収集
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip in ip_set:
                    hostname, model_id = _extract_mdns_info(data, src_ip)
                    if hostname and src_ip not in mdns_results:
                        mdns_results[src_ip] = hostname
                    if model_id and src_ip not in mdns_models:
                        mdns_models[src_ip] = model_id
            except socket.timeout:
                continue
            except Exception:
                break

        sock.close()
    except Exception:
        pass
    finally:
        done_event.set()


# ── NetBIOS（Windows / Samba） ───────────────────────────────────────────────

def get_netbios_name(ip, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        packet = (b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                  b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
                  b'\x00\x21\x00\x01')
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()
        if len(data) < 57:
            return None
        num_names = data[56]
        for i in range(num_names):
            offset     = 57 + i * 18
            if offset + 18 > len(data):
                break
            name_bytes = data[offset:offset + 15]
            name_type  = data[offset + 15]
            flags      = struct.unpack('>H', data[offset + 16:offset + 18])[0]
            if name_type == 0x00 and not (flags & 0x8000):
                name = name_bytes.decode('ascii', errors='ignore').strip()
                if name:
                    return name
        return None
    except Exception:
        return None


# ── デバイス1台の解決（mDNS はバックグラウンド結果を待機） ─────────────────

def resolve_device(ip, mdns_results, mdns_models, done_event):
    """
    DNS → NetBIOS → mDNS待機 の順でホスト名を解決し、
    取れた瞬間に (ip, hostname, model_id) を返す。
    """
    # 1. 逆引き DNS（ほぼ即時）
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return ip, hostname, mdns_models.get(ip)
    except Exception:
        pass

    # 2. NetBIOS（~1秒）
    name = get_netbios_name(ip)
    if name:
        return ip, name, mdns_models.get(ip)

    # 3. mDNS バックグラウンド結果を待機（最大 MDNS_TIMEOUT 秒）
    deadline = time.time() + MDNS_TIMEOUT
    while time.time() < deadline:
        if ip in mdns_results:
            return ip, mdns_results[ip], mdns_models.get(ip)
        if done_event.is_set():
            break
        time.sleep(0.05)

    return ip, mdns_results.get(ip, '-'), mdns_models.get(ip)


# ── ベンダー解決 ────────────────────────────────────────────────────────────

def load_vendor_lookup():
    mac = MacLookup()
    try:
        if not os.path.exists(BaseMacLookup.cache_path):
            print("[*] 初回起動のため、MACアドレス・ベンダーデータベースをダウンロードしています...")
            print("    (数秒〜数十秒かかる場合があります。オフライン時はスキップされます。)")
            mac.update_vendors()
    except Exception as e:
        print(f"[!] ベンダーデータベースのダウンロードをスキップしました: {e}")
    return mac


def resolve_vendor(mac_address, mac_lookup):
    try:
        return mac_lookup.lookup(mac_address)
    except KeyError:
        return "Unknown"
    except Exception:
        return "Unknown"


# ── メイン ──────────────────────────────────────────────────────────────────

def main():
    W = 100
    print("=" * W)
    print("              Wi-Fi 接続デバイス リアルタイム可視化ツール")
    print("=" * W)

    network_cidr, my_ip, interface_name = get_active_network()
    print(f"[*] 使用中のネットワークインターフェース: {interface_name}")
    print(f"[*] ご自身のIPアドレス: {my_ip}")
    print(f"[*] スキャン対象: {network_cidr}")
    print("-" * W)

    mac_lookup = load_vendor_lookup()

    print("[*] ARP スキャンを開始します。応答を待機中...")
    discovered_devices = scan_network(network_cidr)

    if not discovered_devices:
        print("\n[!] デバイスが見つかりませんでした。管理者権限で実行されているか確認してください。")
        return

    ip_list    = [d["ip"] for d in discovered_devices]
    device_map = {d["ip"]: d for d in discovered_devices}

    print(f"[*] {len(discovered_devices)} 台発見。ホスト名と機種情報の解決を開始します...\n")

    # テーブルヘッダーを先に出力
    print("=" * W)
    print("             現時点でWi-Fiに接続されているアクティブなデバイス一覧")
    print("=" * W)
    print(f"{'IPアドレス':<20} | {'デバイス名':<24} | {'機種名':<18} | {'MACアドレス':<18} | メーカー")
    print("-" * W)

    # mDNS リスナーをバックグラウンドスレッドで起動
    mdns_results = {}
    mdns_models  = {}
    done_event   = threading.Event()
    threading.Thread(
        target=start_mdns_listener,
        args=(ip_list, mdns_results, mdns_models, done_event, MDNS_TIMEOUT),
        daemon=True
    ).start()

    # 各デバイスの解決タスクを並列実行 → 完了した行から即座に出力
    resolved_count = 0
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_ip = {
            executor.submit(resolve_device, ip, mdns_results, mdns_models, done_event): ip
            for ip in ip_list
        }
        for future in as_completed(future_to_ip):
            ip, hostname, model_id = future.result()
            device   = device_map[ip]
            vendor   = resolve_vendor(device["mac"], mac_lookup)
            model    = friendly_model(model_id)
            ip_disp  = f"{ip} (本体)" if ip == my_ip else ip

            print(f"{ip_disp:<20} | {hostname:<24} | {model:<18} | {device['mac']:<18} | {vendor}")

            if hostname != '-':
                resolved_count += 1

    print("-" * W)
    print(f"アクティブ: {len(discovered_devices)} 台 / ホスト名取得: {resolved_count} 台")
    print("=" * W)


if __name__ == "__main__":
    main()
