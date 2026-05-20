import os
import math
import socket
import struct
import ipaddress
import scapy.all as scapy
from mac_vendor_lookup import MacLookup, BaseMacLookup
from concurrent.futures import ThreadPoolExecutor

# キャッシュファイルの保存先をローカルディレクトリに変更（権限エラー対策）
BaseMacLookup.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mac-vendors.txt")


def get_active_network():
    try:
        for route_entry in scapy.conf.route.routes:
            network, netmask, _, interface, address = (
                route_entry[0], route_entry[1], route_entry[2],
                route_entry[3], route_entry[4]
            )
            if network == 0 and interface != 'lo' and address != '127.0.0.1':
                if netmask > 0:
                    cidr_prefix = 32 - int(round(math.log2(0xFFFFFFFF - netmask + 1)))
                    net_addr = ipaddress.IPv4Network(f"{address}/{cidr_prefix}", strict=False)
                    return str(net_addr), address, interface
    except Exception as e:
        print(f"[警告] アクティブインターフェースの自動取得に失敗しました: {e}")

    return "192.168.1.0/24", "192.168.1.x", "Default"


def scan_network(ip_range):
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast  = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet     = broadcast / arp_request
    answered   = scapy.srp(packet, timeout=3, retry=1, verbose=False)[0]

    devices = [{"ip": e[1].psrc, "mac": e[1].hwsrc} for e in answered]
    devices.sort(key=lambda x: ipaddress.IPv4Address(x["ip"]))
    return devices


# ── NetBIOS (Windows) ────────────────────────────────────────────────────────

def get_netbios_name(ip, timeout=1):
    """NetBIOS Node Status Request で Windows/Samba 機器のホスト名を取得"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        packet = (
            b'\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            b'\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00'
            b'\x00\x21\x00\x01'
        )
        sock.sendto(packet, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) < 57:
            return None
        num_names = data[56]
        for i in range(num_names):
            offset = 57 + i * 18
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


# ── mDNS / Bonjour (iPhone・Android・Mac など) ───────────────────────────────

def _encode_dns_name(name):
    """ドメイン名を DNS ワイヤー形式にエンコード"""
    encoded = b''
    for label in name.split('.'):
        if label:
            encoded += bytes([len(label)]) + label.encode('ascii')
    return encoded + b'\x00'


def _decode_dns_name(data, offset, depth=0):
    """DNS ワイヤー形式のドメイン名をデコード（圧縮ポインタ対応）"""
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


def get_mdns_name(ip, timeout=2):
    """mDNS ユニキャストクエリで Apple/Android 機器のホスト名を取得"""
    try:
        reversed_ip = '.'.join(reversed(ip.split('.')))
        query_name  = f"{reversed_ip}.in-addr.arpa"
        qname       = _encode_dns_name(query_name)

        # DNS query: standard query, QD=1, PTR IN
        query = b'\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00' + qname + b'\x00\x0c\x00\x01'

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 5353))
        data, _ = sock.recvfrom(4096)
        sock.close()

        if int.from_bytes(data[6:8], 'big') == 0:   # ANCOUNT == 0
            return None

        # 質問セクションを読み飛ばす
        offset = 12
        _, offset = _decode_dns_name(data, offset)
        offset += 4   # QTYPE + QCLASS

        # 回答セクション先頭
        _, offset = _decode_dns_name(data, offset)
        if offset + 10 > len(data):
            return None
        rtype   = int.from_bytes(data[offset:offset + 2], 'big')
        offset += 8   # type(2) + class(2) + ttl(4)
        offset += 2   # RDLENGTH

        if rtype == 12:   # PTR
            name, _ = _decode_dns_name(data, offset)
            name = name.removesuffix('.local').rstrip('.')
            if name:
                return name
        return None
    except Exception:
        return None


# ── ホスト名解決 (優先順位: DNS → NetBIOS → mDNS) ───────────────────────────

def get_hostname(ip):
    # 1. 逆引き DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass

    # 2. NetBIOS（Windows）
    name = get_netbios_name(ip)
    if name:
        return name

    # 3. mDNS（iPhone / Mac / Android）
    name = get_mdns_name(ip)
    if name:
        return name

    return "-"


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

    print("[*] スキャンを開始します。応答を待機中...")
    discovered_devices = scan_network(network_cidr)

    if not discovered_devices:
        print("\n[!] デバイスが見つかりませんでした。管理者権限で実行されているか確認してください。")
        return

    print(f"[*] {len(discovered_devices)} 台発見。ホスト名を解決中 (DNS / NetBIOS / mDNS)...")
    with ThreadPoolExecutor(max_workers=20) as executor:
        hostname_map = {
            ip: future.result()
            for future, ip in [
                (executor.submit(get_hostname, d["ip"]), d["ip"])
                for d in discovered_devices
            ]
        }

    print("\n" + "=" * 90)
    print("         現時点でWi-Fiに接続されているアクティブなデバイス一覧")
    print("=" * 90)
    print(f"{'IPアドレス':<20} | {'デバイス名':<24} | {'MACアドレス':<18} | メーカー")
    print("-" * 90)

    for device in discovered_devices:
        ip      = device["ip"]
        vendor  = resolve_vendor(device["mac"], mac_lookup)
        host    = hostname_map.get(ip, "-")
        ip_disp = f"{ip} (本体)" if ip == my_ip else ip
        print(f"{ip_disp:<20} | {host:<24} | {device['mac']:<18} | {vendor}")

    print("-" * 90)
    print(f"アクティブなデバイス数: {len(discovered_devices)} 台")
    print("=" * 90)


if __name__ == "__main__":
    main()
