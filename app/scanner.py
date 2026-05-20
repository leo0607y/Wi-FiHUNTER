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

MDNS_TIMEOUT = 4.0   # mDNS 収集の最大待機秒数


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
    try:
        if len(data) < 12:
            return None
        qdcount = int.from_bytes(data[4:6],  'big')
        ancount = int.from_bytes(data[6:8],  'big')
        nscount = int.from_bytes(data[8:10], 'big')
        arcount = int.from_bytes(data[10:12],'big')
        if ancount + nscount + arcount == 0:
            return None
        offset = 12
        for _ in range(qdcount):
            _, offset = _decode_dns_name(data, offset)
            offset += 4
        for _ in range(ancount + nscount + arcount):
            if offset >= len(data):
                break
            _, offset = _decode_dns_name(data, offset)
            if offset + 10 > len(data):
                break
            rtype    = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 8
            rdlength = int.from_bytes(data[offset:offset + 2], 'big')
            offset  += 2
            if rtype == 12:  # PTR
                name, _ = _decode_dns_name(data, offset)
                name = name.removesuffix('.local').rstrip('.')
                if name:
                    return name
            offset += rdlength
        return None
    except Exception:
        return None


# ── mDNS バックグラウンドリスナー ────────────────────────────────────────────

def start_mdns_listener(ip_list, mdns_results, done_event, timeout=MDNS_TIMEOUT):
    """
    バックグラウンドスレッドで mDNS クエリをマルチキャスト・ユニキャスト両方に送信し、
    応答を mdns_results dict に書き込む。完了時に done_event をセット。
    """
    ip_set = set(ip_list)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        sock.settimeout(0.1)

        for ip in ip_list:
            reversed_ip = '.'.join(reversed(ip.split('.')))
            qname = _encode_dns_name(f"{reversed_ip}.in-addr.arpa")
            query = (b'\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00'
                     + qname
                     + b'\x00\x0c\x80\x01')  # PTR IN + QU bit
            try:
                sock.sendto(query, ('224.0.0.251', 5353))  # multicast
                sock.sendto(query, (ip, 5353))              # unicast fallback
            except Exception:
                pass

        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                data, (src_ip, _) = sock.recvfrom(4096)
                if src_ip in ip_set and src_ip not in mdns_results:
                    name = _parse_mdns_response(data)
                    if name:
                        mdns_results[src_ip] = name
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


# ── デバイス1台のホスト名解決（mDNS はバックグラウンド結果を待機） ───────────

def resolve_device(ip, mdns_results, done_event):
    """
    DNS → NetBIOS → mDNS(バックグラウンド結果を待機) の順で解決し、
    取れた瞬間に返す。
    """
    # 1. 逆引き DNS（ほぼ即時）
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return ip, hostname
    except Exception:
        pass

    # 2. NetBIOS（~1秒）
    name = get_netbios_name(ip)
    if name:
        return ip, name

    # 3. mDNS バックグラウンドの結果を待機（最大 MDNS_TIMEOUT 秒）
    deadline = time.time() + MDNS_TIMEOUT
    while time.time() < deadline:
        if ip in mdns_results:
            return ip, mdns_results[ip]
        if done_event.is_set():
            break
        time.sleep(0.05)

    return ip, mdns_results.get(ip, "-")


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

    ip_list    = [d["ip"] for d in discovered_devices]
    device_map = {d["ip"]: d for d in discovered_devices}

    print(f"[*] {len(discovered_devices)} 台発見。ホスト名解決を開始します...\n")

    # テーブルヘッダーを先に出力
    header = f"{'IPアドレス':<20} | {'デバイス名':<26} | {'MACアドレス':<18} | メーカー"
    sep    = "-" * 90
    print("=" * 90)
    print("         現時点でWi-Fiに接続されているアクティブなデバイス一覧")
    print("=" * 90)
    print(header)
    print(sep)

    # mDNS リスナーをバックグラウンドスレッドで起動
    mdns_results = {}
    done_event   = threading.Event()
    mdns_thread  = threading.Thread(
        target=start_mdns_listener,
        args=(ip_list, mdns_results, done_event, MDNS_TIMEOUT),
        daemon=True
    )
    mdns_thread.start()

    # 各デバイスの解決タスクを並列実行 → 完了した行からすぐに出力
    resolved_count = 0
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_ip = {
            executor.submit(resolve_device, ip, mdns_results, done_event): ip
            for ip in ip_list
        }

        for future in as_completed(future_to_ip):
            ip, hostname = future.result()
            device  = device_map[ip]
            vendor  = resolve_vendor(device["mac"], mac_lookup)
            ip_disp = f"{ip} (本体)" if ip == my_ip else ip

            print(f"{ip_disp:<20} | {hostname:<26} | {device['mac']:<18} | {vendor}")

            if hostname != "-":
                resolved_count += 1

    print(sep)
    print(f"アクティブなデバイス数: {len(discovered_devices)} 台 / ホスト名取得: {resolved_count} 台")
    print("=" * 90)


if __name__ == "__main__":
    main()
