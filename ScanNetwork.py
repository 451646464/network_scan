from scapy.all import ARP, Ether, srp, IP, TCP, sr
import psutil
import sys
import time
from datetime import datetime
import speedtest


def get_device_type(mac_address):
    """تحديد نوع الجهاز بناءً على عنوان MAC."""
    vendor_lookup = {
        '00:1A': 'Apple',
        '00:1B': 'Microsoft',
        '00:1C': 'Cisco',
        '00:1D': 'Dell',
        '00:1E': 'Samsung',
    }

    for prefix in vendor_lookup:
        if mac_address.startswith(prefix):
            return vendor_lookup[prefix]

    return 'Unknown'


def get_os_type(ip):
    """تحديد نظام التشغيل بناءً على استجابة TCP."""
    packet = IP(dst=ip) / TCP(dport=80, flags='S')
    response = sr(packet, timeout=2, verbose=0)[0]

    if response:
        for sent, received in response:
            if received.haslayer(TCP):
                if received[TCP].flags == 18:  # SYN+ACK
                    if received[TCP].options:
                        for option in received[TCP].options:
                            if option[0] == 'MSS':
                                return "Linux/Unix"
                            elif option[0] == 'WScale':
                                return "Windows"
    return "Unknown"


def scan_ports(ip):
    """مسح البورتات المفتوحة للجهاز."""
    open_ports = []
    for port in range(1, 1024):  # مسح البورتات من 1 إلى 1023
        packet = IP(dst=ip) / TCP(dport=port, flags='S')
        response = sr(packet, timeout=1, verbose=0)[0]

        for sent, received in response:
            if received.haslayer(TCP) and received[TCP].flags == 18:  # SYN+ACK
                open_ports.append(port)

    return open_ports


def get_network_usage(ip):
    """الحصول على البيانات المرسلة والمستقبلة للجهاز باستخدام psutil."""
    net_io = psutil.net_io_counters(pernic=True)
    data = net_io.get(ip, None)
    if data:
        return data.bytes_sent, data.bytes_recv
    return 0, 0


def measure_speed():
    """قياس سرعة التحميل والرفع باستخدام speedtest."""
    st = speedtest.Speedtest()
    st.download()
    st.upload()
    return st.results.download / 1_000_000, st.results.upload / 1_000_000  # تحويل إلى ميغابت في الثانية


def scan_network(ip_range):
    # إعداد حزمة ARP
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    # إرسال الحزمة واستقبال الردود
    result = srp(packet, timeout=3, verbose=0)[0]

    # تخزين العناوين المستلمة
    devices = []
    start_time = datetime.now()  # تسجيل وقت البدء
    for sent, received in result:
        device_type = get_device_type(received.hwsrc)
        os_type = get_os_type(received.psrc)
        open_ports = scan_ports(received.psrc)
        bytes_sent, bytes_recv = get_network_usage(received.psrc)
        connection_time = datetime.now() - start_time  # حساب وقت الاتصال
        download_speed, upload_speed = measure_speed()  # قياس السرعة
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'type': device_type,
            'os': os_type,
            'open_ports': open_ports,
            'bytes_sent': bytes_sent,
            'bytes_recv': bytes_recv,
            'connection_time': str(connection_time),
            'download_speed': download_speed,
            'upload_speed': upload_speed
        })

    return devices


def display_results(devices):
    print("العناوين الموجودة على الشبكة:")
    print("{:<20} {:<20} {:<20} {:<20} {:<30} {:<20} {:<20} {:<20} {:<20} {:<20}".format(
        "IP Address", "MAC Address", "Device Type", "OS Type", "Open Ports", "Bytes Sent", "Bytes Recv",
        "Connection Time", "Download Speed (Mbps)", "Upload Speed (Mbps)"))
    print("-" * 180)
    for device in devices:
        open_ports_str = ', '.join(map(str, device['open_ports'])) if device['open_ports'] else 'None'
        print("{:<20} {:<20} {:<20} {:<20} {:<30} {:<20} {:<20} {:<20} {:<20} {:<20}".format(
            device['ip'], device['mac'], device['type'], device['os'], open_ports_str,
            device['bytes_sent'], device['bytes_recv'], device['connection_time'],
            f"{device['download_speed']:.2f}", f"{device['upload_speed']:.2f}"))
    print("\nتم الانتهاء من المسح.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("يرجى إدخال نطاق IP للمسح مثل: python3 scan.py 192.168.1.1/24")
        sys.exit(1)

    ip_range = sys.argv[1]
    devices = scan_network(ip_range)
    display_results(devices)