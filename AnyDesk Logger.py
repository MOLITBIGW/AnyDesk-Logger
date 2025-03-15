import subprocess
import re
import time
from datetime import datetime
from colorama import init, Fore, Style
import pyfiglet
import os
import threading
import requests

init(autoreset=True)

def get_ip_info(ip_address):
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return data
            else:
                return None
        else:
            return None
    except Exception as e:
        log_message(Style.BRIGHT + Fore.RED + f"Error fetching IP info: {e}")
        return None

def generate_log_filename():
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return f"ip_{timestamp}.log"

LOG_FILE = generate_log_filename()

def log_message(message):
    timestamp = datetime.now().strftime("[%H:%M:%S]")
    formatted_message = f"{timestamp} {message}"
    print(formatted_message)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(formatted_message + "\n")

def parse_netstat_output_targeted(target_process_name):
    try:
        result = subprocess.run(['netstat', '-ano'], stdout=subprocess.PIPE, text=True)
        output = result.stdout
        netstat_pattern = re.compile(r'\s+TCP\s+([\d.]+):(\d+)\s+([\d.]+):(\d+)\s+ESTABLISHED\s+(\d+)')
        matches = netstat_pattern.findall(output)

        for match in matches:
            local_ip, local_port, remote_ip, remote_port, pid = match

            if remote_ip == "0.0.0.0" or remote_port in {"0", "80", "443"}:
                continue

            try:
                process_name = subprocess.run(
                    ['tasklist', '/FI', f'PID eq {pid}'],
                    stdout=subprocess.PIPE, text=True
                ).stdout

                if target_process_name.lower() in process_name.lower():
                    print(Style.BRIGHT + Fore.YELLOW + "-" * 40)
                    log_message(Style.BRIGHT + Fore.GREEN + f"Process: {target_process_name}")

                    ip_info = get_ip_info(remote_ip)
                    if ip_info:
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Remote IP: {remote_ip}, Port: {remote_port}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Country: {ip_info.get('country', 'N/A')} ({ip_info.get('countryCode', 'N/A')})")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Region: {ip_info.get('regionName', 'N/A')} ({ip_info.get('region', 'N/A')})")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"City: {ip_info.get('city', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"ZIP: {ip_info.get('zip', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Coordinates: Lat {ip_info.get('lat', 'N/A')}, Lon {ip_info.get('lon', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Timezone: {ip_info.get('timezone', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"ISP: {ip_info.get('isp', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Organization: {ip_info.get('org', 'N/A')}")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"AS: {ip_info.get('as', 'N/A')})")
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Query: {ip_info.get('query', 'N/A')}")
                    else:
                        log_message(Style.BRIGHT + Fore.LIGHTCYAN_EX + f"Remote IP: {remote_ip}, Port: {remote_port} (No additional info available)")

                    log_message(Style.BRIGHT + Fore.GREEN + f"PID: {pid}")
                    print(Style.BRIGHT + Fore.YELLOW + "-" * 40)

            except Exception as ex:
                log_message(Style.BRIGHT + Fore.RED + f"Error processing PID {pid}: {ex}")

    except Exception as e:
        log_message(Style.BRIGHT + Fore.RED + f"Error executing netstat: {e}")

def monitor_targeted_connections(target_process_name, stop_event):
    while not stop_event.is_set():
        parse_netstat_output_targeted(target_process_name)
        time.sleep(1)

def main_menu():
    print(Style.BRIGHT + Fore.BLUE + "1. Start Sniff")
    print(Style.BRIGHT + Fore.YELLOW + "-" * 40)

    choice = input(Style.BRIGHT + Fore.WHITE + "Type 1 To Start: ")

    while True:
        if choice == "1":
            log_message(Style.BRIGHT + Fore.GREEN + "Starting sniffing...")
            monitor_menu()
            break  
        else:
            log_message(Style.BRIGHT + Fore.RED + "Invalid choice. Try again.")
            choice = input(Style.BRIGHT + Fore.WHITE + "Type 1 To Start: ") 


def monitor_menu():
    stop_event = threading.Event()
    target_process_name = "AnyDesk"
    sniff_thread = threading.Thread(target=monitor_targeted_connections, args=(target_process_name, stop_event))
    sniff_thread.start()

if __name__ == "__main__":
    log_message(f"Program started. Logs Will Be Saved In: {LOG_FILE}")
    main_menu()
