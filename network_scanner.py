import socket
from tkinter import *
from tkinter import ttk
from scapy.all import ARP, Ether, srp
import nmap
import threading

# Функция для сканирования сети и получения MAC-адресов
def scan_network(ip_range, progress_var, progress_bar):
    progress_var.set(10)
    update_progress(progress_bar)
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    progress_var.set(50)
    update_progress(progress_bar)
    return devices

# Функция для сканирования открытых портов на локальном компьютере
def scan_local_ports(progress_var, progress_bar):
    open_ports = []
    progress_var.set(0)
    update_progress(progress_bar)
    for port in range(1, 1000):  # Ограничиваем диапазон для ускорения
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.05)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                open_ports.append(port)
        progress = int((port / 1000) * 100)
        progress_var.set(progress)
        update_progress(progress_bar)
    return open_ports

# Функция для сканирования портов и служб в сети
def scan_ports_and_services(ip_range, progress_var, progress_bar):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sV')
    results = {}
    hosts = nm.all_hosts()
    for i, host in enumerate(hosts):
        progress = int(((i + 1) / len(hosts)) * 100)
        progress_var.set(progress)
        update_progress(progress_bar)
        host_info = {
            'status': nm[host].state(),
            'open_ports': []
        }
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                host_info['open_ports'].append({
                    'port': port,
                    'service': nm[host][proto][port]['name'],
                    'product': nm[host][proto][port].get('product', ''),
                    'version': nm[host][proto][port].get('version', '')
                })
        results[host] = host_info
    return results

# Обновление прогресс-бара
def update_progress(progress_bar):
    progress_bar.update_idletasks()

# Основной поток для выполнения задач
def run_tasks():
    # Обновление интерфейса
    result_text.delete(1.0, END)
    progress_var.set(0)
    update_progress(progress_bar)

    # Получение IP-диапазона
    ip_range = ip_range_entry.get()

    # Сканирование сети
    result_text.insert(END, "Сканирование сети...\n")
    devices = scan_network(ip_range, progress_var, progress_bar)
    result_text.insert(END, "Найденные устройства:\n")
    for device in devices:
        result_text.insert(END, f"IP: {device['ip']}, MAC: {device['mac']}\n")

    # Сканирование портов локального компьютера
    result_text.insert(END, "\nСканирование локальных портов...\n")
    local_open_ports = scan_local_ports(progress_var, progress_bar)
    result_text.insert(END, f"Открытые порты: {local_open_ports}\n")

    # Сканирование портов и служб в сети
    result_text.insert(END, "\nСканирование служб в сети...\n")
    network_services = scan_ports_and_services(ip_range, progress_var, progress_bar)
    for host, info in network_services.items():
        result_text.insert(END, f"Хост: {host}, Статус: {info['status']}\n")
        for port_info in info['open_ports']:
            result_text.insert(END, f"  Порт: {port_info['port']}, Сервис: {port_info['service']}, "
                                    f"Продукт: {port_info['product']}, Версия: {port_info['version']}\n")

    result_text.insert(END, "\nСканирование завершено!\n")
    progress_var.set(100)
    update_progress(progress_bar)

# Настройка GUI
root = Tk()
root.title("Сканер сети и портов")
root.geometry("800x600")

# Поле для ввода IP-диапазона
ip_range_label = Label(root, text="Введите диапазон IP (например, 192.168.1.0/24):")
ip_range_label.pack(pady=5)
ip_range_entry = Entry(root, width=50)
ip_range_entry.pack(pady=5)
ip_range_entry.insert(0, "192.168.1.0/24")

# Кнопка запуска
start_button = Button(root, text="Запустить сканирование", command=lambda: threading.Thread(target=run_tasks).start())
start_button.pack(pady=10)

# Прогресс-бар
progress_var = IntVar()
progress_bar = ttk.Progressbar(root, orient=HORIZONTAL, length=600, mode='determinate', variable=progress_var)
progress_bar.pack(pady=10)

# Текстовое поле для вывода результатов
result_text = Text(root, wrap=WORD, height=25, width=80)
result_text.pack(pady=10)

# Запуск основного цикла GUI
root.mainloop()
