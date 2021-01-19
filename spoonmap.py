#!/usr/bin/env python3

# Author: Spoonman (Larry.Spohn@TrustedSec.com)
# QA and Personal Pythonian Consultant: Bandrel (Justin.Bollinger@TrustedSec.com)

import json
import os
import subprocess
import xml.etree.ElementTree as etree


def verify_python_version():
    import sys
    if sys.version_info[0] == 2:
        print('Python 3.6+ is required')
        quit(1)
    elif sys.version_info[0] == 3 and sys.version_info[1] < 6:
        print('Python 3.6+ is required')
        quit(1)


def ascii_art():
    print(r'''
________                   _____   _______  _________________ 
__  ___/______________________  | / /__   |/  /__    |__  __ \
_____ \___  __ \  __ \  __ \_   |/ /__  /|_/ /__  /| |_  /_/ /
____/ /__  /_/ / /_/ / /_/ /  /|  / _  /  / / _  ___ |  ____/ 
/____/ _  .___/\____/\____//_/ |_/  /_/  /_/  /_/  |_/_/      
       /_/                                                 
    ''')

def mass_scan(scan_type, dest_ports, source_port, max_rate, target_file):
    status_summary = '\nSummary'

    if not os.path.exists('masscan_results'):
        os.makedirs('masscan_results')
    for dest_port in dest_ports:

        # Commence masscan!
        print('\x1b[33m' + f'Scanning port {dest_port}...' + '\x1b[0m')
        masscan_process = subprocess.Popen(f'masscan -p {dest_port} --open --max-rate {max_rate} ' \
            f'--source-port {source_port} -iL {target_file} -oX {dir_path}/masscan_results/port{dest_port}.xml',
            shell=True)
        try:
           masscan_process.wait()
        except KeyboardInterrupt:
            print(f'Killing PID {str(masscan_process.pid)}...')
        if masscan_process.returncode == 1:
            quit(1)

        # Parse results from masscan
        if os.stat(f'{dir_path}/masscan_results/port{dest_port}.xml').st_size == 0:
            os.remove(f'masscan_results/port{dest_port}.xml')
            print('\x1b[33m' + f'\nHosts Found on Port {dest_port}: 0')
            print('Masscan Completion Status: ' + '{:.0%}'.format((dest_ports.index(dest_port) + 1) / len(dest_ports)) + '\x1b[0m')
        else:
            root = etree.parse(f'{dir_path}/masscan_results/port{dest_port}.xml')
            hosts = root.findall('host')
            for host in hosts:
                ip_address = host.findall('address')[0].attrib['addr']
                live_port = host.findall('ports/port')[0].attrib['portid']

                # Write live hosts out to file
                if not os.path.exists(f'{dir_path}/live_hosts'):
                    os.makedirs(f'{dir_path}/live_hosts')
                if os.path.exists(f'{dir_path}/live_hosts/port{live_port}.txt'):
                    with open(f'{dir_path}/live_hosts/port{live_port}.txt') as file:
                        ip_exists = False
                        if f'{ip_address}\n' in file.read():
                            ip_exists = True
                    if not ip_exists:
                        with open(f'{dir_path}/live_hosts/port{live_port}.txt', 'a') as file:
                            file.write(f'{ip_address}\n')
                else:
                    with open(f'{dir_path}/live_hosts/port{live_port}.txt', 'w') as file:
                        file.write(f'{ip_address}\n')
            host_count = lineCount(f'{dir_path}/live_hosts/port{live_port}.txt')
            status_update = f'\nHosts Found on Port {dest_port}: {host_count}'
            status_summary += status_update
            print('\x1b[33m' + status_update)
            print('Masscan Completion Status: ' + '{:.0%}'.format((dest_ports.index(dest_port) + 1) / len(dest_ports)) + '\x1b[0m')

    return status_summary

def nmap_scan(source_port):

    # Commence NMAP banner grabbing!
    if not os.path.exists(f'{dir_path}/nmap_results'):
        os.makedirs(f'{dir_path}/nmap_results')
    try:
        host_files = os.listdir('live_hosts')
        for host_file in host_files:
            dest_port = ((host_file.split('.')[0])[4:])
            if not os.path.exists(f'{dir_path}/nmap_results/port{dest_port}.xml'):
                print('\x1b[33m' + f'Grabbing service banners for port {dest_port}...\n' + '\x1b[0m')
                nmap_process = subprocess.Popen(f'nmap -T4 -sS -sV --version-intensity 0 -Pn -p {dest_port} --open ' \
                    f'--randomize-hosts --source-port {source_port} -iL {dir_path}/live_hosts/port{dest_port}.txt ' \
                    f'-oX {dir_path}/nmap_results/port{dest_port}.xml',
                    shell=True)
                try:
                    nmap_process.wait()
                    print('\x1b[33m' + '\nNMAP Completion Status: ' + \
                        '{:.0%}'.format((host_files.index(host_file) + 1) / len(host_files)) + \
                        '\x1b[0m')
                except KeyboardInterrupt:
                    print(f'Killing PID {str(nmap_process.pid)}...')
    except:
        pass

# Counts the number of lines in a file
def lineCount(file):
    try:
        with open(file) as outFile:
            count = 0
            for line in outFile:
                count = count + 1
        return count
    except:
        return 0


# The Main Guts
def main():
    global dir_path
    ascii_art()

    scan_type = ''
    dest_ports = []
    banner_scan = ''
    target_scan = ''
    source_port = '53'
    max_rate = ''
    target_file = ''
    status_summary = ''


    # Get options from configuration file if it exists
    dir_path = os.path.dirname(os.path.realpath(__file__))
    if os.path.exists(f'{dir_path}/config.json'):
        with open(f'{dir_path}/config.json') as config:
            config_parser = json.load(config)

        scan_type = config_parser['scan_type']
        dest_ports = config_parser['dest_ports']
        banner_scan = config_parser['banner_scan']
        if banner_scan == 'True':
            banner_scan = True
        else:
            banner_scan = False
        target_scan = config_parser['target_scan']
        max_rate = config_parser['max_rate']
        target_file = config_parser['target_file']

    if scan_type == '':
        scan_choice = '1'
        while True:
            print('\nScan Type')
            print('\t(1) Small Port Scan')
            print('\t(2) Medium Port Scan')
            print('\t(3) Large Port Scan')
            print('\t(4) Extra Large Port Scan (Small, Medium, and Large)')
            print('\t(5) Full Port Scan')
            print('\t(6) Custom Port Scan')
            scan_choice = input(
                f'\nWhat type of scan would you like to perform (default: Small Port Scan)? '
                ) or scan_choice
            if scan_choice == '1':
                scan_type = 'Small Port Scan'
                break
            elif scan_choice == '2':
                scan_type = 'Medium Port Scan'
                break
            elif scan_choice == '3':
                scan_type = 'Large Port Scan'
                break
            elif scan_choice == '4':
                scan_type = 'Extra Large Port Scan'
                break
            elif scan_choice == '5':
                scan_type = 'Full Port Scan'
                break
            elif scan_choice == '6':
                scan_type = 'Custom Port Scan'
                break

    small_ports = ['80', '443', '8000', '8080', '8008', '8181', '8443']
    medium_ports = ['7001', '1433', '445', '139', '21', '22', '23', '25', 
                '53', '111', '389', '4243', '3389', '3306', '4786', 
                '5900', '5901', '5985', '5986', '6379', '6970', '9100']
    large_ports = ['1090', '1098', '1099', '10999', '11099', '11111', 
                '3300', '4243', '4444', '4445', '45000', '45001', 
                '47001', '47002', '4786', '4848', '50500', '5555', 
                '5556', '6129', '6379', '6970', '7000', 
                '7002', '7003', '7004', '7070', '7071', 
                '8001', '8002', '8003', '8686', '9000', 
                '9001', '9002', '9003', '9012', '9503']
    if scan_type == 'Small Port Scan':
        dest_ports = small_ports
    elif scan_type == 'Medium Port Scan':
        dest_ports = medium_ports
    elif scan_type == 'Large Port Scan':
        dest_ports = large_ports
    elif scan_type == 'Extra Large Port Scan':
        dest_ports = small_ports + medium_ports + large_ports
    elif scan_type == 'Full Port Scan':
        dest_ports = ['1-65535']
    elif scan_type == 'Custom Port Scan' and not dest_ports:
        dest_ports = input(
            '\nWhat ports would you like to scan (separated by space: 80 443)? ').split()

    if banner_scan == '':
        banner_choice = 1
        banner_choice = input(
            f'\nWould you like to enumerate service banners for any identified services '
            f'(default: Yes)? '
            ) or banner_choice
        if banner_choice == 1 or banner_choice[0].lower() == 'y':
            banner_scan = True
        else:
            banner_scan = False

    if not target_scan:
        source_choice = '1'
        while True:
            print('\nTarget Scan')
            print('\t(1) External')
            print('\t(2) Internal')
            source_choice = input(
                f'\nIs this an internal or external scan '
                f'(default: External)? '
                ) or source_choice
            if source_choice == '1':
                target_scan = 'External'
                source_port = '53'
                break
            elif source_choice == '2':
                target_scan = 'Internal'
                source_port = '88'
                break

    if not max_rate:
        if target_scan == "External" and scan_type == "Small Port Scan":
            max_rate = '20000'
        elif target_scan == "External" and scan_type == "Full Port Scan":
            max_rate = '10000'
        elif target_scan == "Internal" and scan_type == "Small Port Scan":
            max_rate = '2000'
        elif target_scan == "Internal" and scan_type == "Full Port Scan":
            max_rate = '1000'
        else:
            max_rate = '2000'
        while True:
            try:
                rate_choice = input(f'\nHow fast would you like to scan '
                    f'(default: {max_rate} packets/second)? '
                    ) or max_rate
                if int(rate_choice):
                    max_rate = rate_choice
                    break
            except ValueError:
                pass

    if not target_file:
        target_file = 'ranges.txt'
        while True:
            print('\nExample Target File')
            print('One CIDR or IP Address per line\n')
            print('\t192.168.0.0/24')
            print('\t192.168.1.23')
            target_file = input(f'\nPlease enter the full path for the file '
                f'containing target hosts (default: {dir_path}/{target_file}): '
                ) or target_file
            if os.path.exists(target_file):
                break

    print(f'\nScan Type: {scan_type}')
    print(f'Target Ports: {dest_ports}')
    print(f'Service Banner: {banner_scan}')
    print(f'Source Port: {source_port}')
    print(f'Masscan Max Packet Rate (pps): {max_rate}')
    print(f'Target File: {target_file}\n')

    status_summary = mass_scan(scan_type, dest_ports, source_port, max_rate, target_file)

    # If service banners requested, send to nmap
    if banner_scan or banner_scan == 'Yes':
        nmap_scan(source_port)

    # Combine all live hosts into one file
    all_ips = set()
    if os.path.exists(f'{dir_path}/live_hosts'):
        host_files = os.listdir(f'{dir_path}/live_hosts')
        for host_file in host_files:
            with open(f'{dir_path}/live_hosts/{host_file}') as input_file:
                for line in input_file:
                    all_ips.add(line)
        with open(f'{dir_path}/all_live_hosts.txt', 'w') as output_file:
            for ip in all_ips:
                output_file.write(ip)

        # Combine all XML results into one file
        if banner_scan :
            result_dir = f'{dir_path}/nmap_results/'
        else:
            result_dir = f'{dir_path}/masscan_results/'
        xml_result = '<?xml version="1.0"?>\n<!-- SpooNMAP -->\n<nmaprun>\n'
        xml_files = os.listdir(result_dir)
        for xml_file in xml_files:
            root = etree.parse(result_dir + xml_file)
            hosts = root.findall('host')
            for host in hosts:
                xml_result += etree.tostring(host, encoding="unicode", method="xml")
        xml_result += '</nmaprun>'
        with open(f'{dir_path}/spoonmap_output.xml', 'w+') as spoonmap_output:
            spoonmap_output.write(xml_result)
        print('\x1b[33m' + f'\nResults written to {dir_path}/spoonmap_output.xml' + '\x1b[0m')

    else:
        status_summary += '\nNo hosts found.'

    # Print Summary
    print('\x1b[33m' + status_summary + '\x1b[0m')

# Boilerplate
if __name__ == '__main__':
    verify_python_version()
    main()
