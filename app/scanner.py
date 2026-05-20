import os
import math
import time
import socket
import struct
import ipaddress
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, BaseMacLookup
from concurrent.futures import ThreadPoolExecutor

BaseMacLookup.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")


# ── ネットワーク検出 ─────────────────────────────────────────────────────────

def get_active_network():
    """
    scapy.conf.iface（デフォルトインターフェース）を基点に
    アクティブなネットワーク CIDR を取得する。
    """
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


# ── DNS ユーティリティ ────────────────────────────────────────────────────────

def _encode_dns_name(name):
    encoded = b''
    for label in name.split('.'):
        if label:
            encoded += bytes([len(label)]) + label.encode('ascii')
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
        labels.append(data[offset:offset + length].decode('utf-8', errors='replace'))
        offset += length
    return '.'.join(labels), offset


def _parse_mdns_response(data):
    """
    mDNS レスポンスから PTR レコードのホスト名を抽出する。
    回答セクションと追加セクション両方を走査する。
    """
    try:
        if len(data) < 12:
            return None

        qdcount = int.from_bytes(data[4:6],  'big')
        ancount = int.from_bytes(data[6:8],  'big')
        nscount = int.from_bytes(data[8:10], 'big')
        arcount = int.from_bytes(data[10:12],'big')
        total   = ancount + nscount + arcount

        if total == 0:
            return None

        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_dns_name(data, offset)
            offset += 4

        for _ in range(total):
            if offset >= len(data):
                break
            _, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype    = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 8                                              # type + class + ttl
            rdlength = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 2

            if rtype == 12:   # PTR
                name, _ = _decode_dns_name(data, offset)
                name = name.removesuffix('.local').rstrip('.')
                if name:
                    return name

            offset += rdlength

        return None
    except Exception:
        return None


# ── mDNS バッチ収集（iPhone / Mac / Android / Linux Avahi） ──────────────────

def collect_mdns_names_batch(ip_list, timeout=4):
    """
    全デバイスに対して mDNS PTR クエリを
      ① マルチキャスト (224.0.0.251:5353) — iPhoneなどが期待するアドレス
      ② ユニキャスト (各IP:5353)           — フォールバック
    で一括送信し、返答を集約する。
    QU ビット (0x8001) を立てることでユニキャスト応答を誘導する。
    """
    names  = {}
    ip_set = set(ip_list)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.1)

        # 全 IP にクエリ送信
        for ip in ip_list:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            qname       = _encode_dns_name(f"{reversed_ip}.in-addr.arpa")
            # QU ビット付き PTR IN クエリ
            query = (b'\x00\x00'           # Transaction ID
                     b'\x00\x00'           # Flags: standard query
                     b'\x00\x01'           # QDCOUNT = 1
                     b'\x00\x00\x00\x00\x00\x00'  # AN/NS/AR = 0
                     + qname
                     + b'\x00\x0c'         # QTYPE  = PTR
                     + b'\x80\x01')        # QCLASS = IN + QU bit
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
                if src_ip in ip_set and src_ip not in names:
                    name = _parse_mdns_response(data)
                    if name:
                        names[src_ip] = name
            except socket.timeout:
                continue
            except Exception:
                break

        sock.close()
    except Exception:
        pass

    return names


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


# ── DNS + NetBIOS フォールバック ─────────────────────────────────────────────

def get_hostname_fallback(ip):
    """逆引き DNS → NetBIOS の順で解決（mDNS は事前バッチで収集済み）"""
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass
    name = get_netbios_name(ip)
    return name if name else "-"


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
        return "Unknown Device (未登録)"
    except Exception:
        return "Unknown (検索エラー)"


# ── メイン ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 80)
    print("          Wi-Fi 接続デバイス リアルタイム可視化ツール")
    print("=" * 80)

    network_cidr, my_ip, interface_name = get_active_network()
    print(f"[*] 使用中のネットワークインターフェース: {interface_name}")
    print(f"[*] ご自身のIPアドレス: {my_ip}")
    print(f"[*] スキャン対象: {network_cidr}")
    print("-" * 80)

    mac_lookup = load_vendor_lookup()

    print("[*] ARP スキャンを開始します。応答を待機中...")
    discovered_devices = scan_network(network_cidr)

    if not discovered_devices:
        print("\n[!] デバイスが見つかりませんでした。管理者権限で実行されているか確認してください。")
        return

    ip_list = [d["ip"] for d in discovered_devices]
    print(f"[*] {len(discovered_devices)} 台発見。")

    # ① mDNS バッチ収集（iPhone / Mac / Android / Linux が主なターゲット）
    print("[*] mDNS (Bonjour) でホスト名を収集中... (最大4秒)")
    mdns_names = collect_mdns_names_batch(ip_list, timeout=4)
    mdns_count = len(mdns_names)
    print(f"    → mDNS: {mdns_count} 台取得")

    # ② mDNS で取れなかった分を DNS + NetBIOS で並列解決
    remaining = [ip for ip in ip_list if ip not in mdns_names]
    print(f"[*] DNS / NetBIOS で残り {len(remaining)} 台を解決中...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        fallback_map = {
            ip: future.result()
            for future, ip in [
                (executor.submit(get_hostname_fallback, ip), ip)
                for ip in remaining
            ]
        }

    hostname_map = {**mdns_names, **fallback_map}

    # 集計
    resolved = sum(1 for v in hostname_map.values() if v != "-")
    print(f"    → 合計 {resolved} / {len(ip_list)} 台のホスト名を取得。\n")

    print("=" * 90)
    print("         現時点でWi-Fiに接続されているアクティブなデバイス一覧")
    print("=" * 90)
    print(f"{'IPアドレス':<20} | {'デバイス名':<26} | {'MACアドレス':<18} | メーカー")
    print("-" * 90)

    for device in discovered_devices:
        ip      = device["ip"]
        vendor  = resolve_vendor(device["mac"], mac_lookup)
        host    = hostname_map.get(ip, "-")
        ip_disp = f"{ip} (本体)" if ip == my_ip else ip
        print(f"{ip_disp:<20} | {host:<26} | {device['mac']:<18} | {vendor}")

    print("-" * 90)
    print(f"アクティブなデバイス数: {len(discovered_devices)} 台 / ホスト名取得: {resolved} 台")
    print("=" * 90)


if __name__ == "__main__":
    main()
