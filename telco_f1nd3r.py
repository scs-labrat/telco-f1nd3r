import os
import re
import subprocess
import shutil
from termcolor import colored
import pyfiglet
import sys
import select
import json
import shodan
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

# List of ports and their corresponding protocols with color codes
port_protocol_mapping = {
    3868: [("Diameter", 'cyan')],
    2905: [("M3UA (Sigtran)", 'green')],
    2915: [("SUA (Sigtran)", 'yellow')],
    36412: [("SCTP Heartbeat", 'magenta')],
    1812: [("RADIUS (Diameter Compatibility)", 'blue')],
    1813: [("RADIUS Accounting (Diameter Compatibility)", 'red')],
    3565: [("M2PA (Sigtran)", 'cyan')],
    2904: [("M2UA (Sigtran)", 'green')],
    9900: [("IUA (ISDN User Adaptation)", 'yellow')],
    2944: [("H.248/MEGACO", 'magenta')],
    2123: [("GTP-C (GPRS Tunneling Protocol)", 'blue')],
    2152: [("GTP-U (GPRS Tunneling Protocol)", 'red')]
}

# Add additional protocols to ports that can have multiple
port_protocol_mapping[1812].append(("DIAMETER Authentication", 'cyan'))
port_protocol_mapping[2152].append(("GTP-U (LTE)", 'green'))

# ASCII Vanity Banner
def ascii_banner():
        os.system("clear")
        print(''''       
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@              @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@  TELCO       @@@@@@@@@@@@@@@@@@@@@@@@@&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@  F1ND3R      @@@@@@@@@@@@@@@@@@@@@@G^~5BBYG&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@
        @@@@@  by d8rh8r   @@@@@@@@@@@@@@@@@@@@!.^^.:!!!JYJ?5JB&&&&&&&@@@@@@@@@@@@@@@@@@
        @@@@@              @@@@@@@@@@@@@@@@@@&:.:::::~!~7PPJ7?#&&&&BG&&&&@@@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&^..:::::~~^!5PY!J#BB&@&5J#&&&&@@@@@@@@@@@@@
        @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@^...::::^^~^~!?JJYG5P&@&5!5&&&&&&@@@@@@@@@@@
        &@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@7.:..::::^^~~~~!7Y5Y?P&@B7!J#&&###&@@@@@@@@@@
        &&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@P.:::..::::^~~~~~~7JJJ5B#J?YY#&&#&&##@@@@@@@@@
        &&&&&@@@@@@@@@@@@@@@@@@@@@@@@@@@@#.:^^:...:.::^~!~~!?YPG##&&@@@@@@@&###B@@@@@@@@
        &&&&&&&&@@@@@@@@@@@@@@@@@@@@@@@@&^.^!~::..:..::^7P#&@@@@@@@@@@@@@@@@&#&##@@@@@@@
        &&&&&&&@@@@@@@@@@@@@@@@@@@@@@@@@!..^!!^:::...^P&@@@@@@@@@@@@@@@@@@@@@@@&##@@@@@@
        &&&&&&&&@@@@@@@@@@@@@@@@@@@@@@@?::.^!!^:~::7#@@@@@@@@@@@@@@@@@@@@@@@@@@@&P#@@@@@
        &&&&&&&&&&&&&@@@@@@@@@@@@@@@@@B.:..^7~::^?&@@@@@@@@@@@@@@@@@@@@@@@@@@@@@&G?@@@@@
        &&&&&&&&&&&&&&&&&@@@@@@@@@@@@@~....~~::?#@&&&@@@@@@@@@@@@@@@@@@@@@@@@@@&#P?@@@@@
        &&&&&&&&&&&&&&&&&&&@@@@@@@@@@G....:::J&@@&P?!^^~7?J5PG#&&&&&&@@@@@@@@@@&BYY@@@@@
        &&&&&&&&&&&&&&&&&&&@@@@@@@@@&:.....7&@@@&BY!^:......:~?Y5YYY#@@@@@@@@@&#PJ#@@@@@
        #&&&&&&&&&&&&&@@@@@@@@@@@@@@#.....5@@@@@@BJ!~:.......^YP55YB@@@@@@@@@@&GP&@@@@@@
        #&&&&&&&&&@@@@@@@@@@@@@@@@@@&^...J@@@@@@@@P5@?:YJ:^^:^JPPP#@@@@@@@@@@@#B@@@@@@@@
        &&&&&&&&@@@@@@@@@@@@@&&#GPJYY~..:&@@@@@@@@#G@Y.5@!@#.!&&#&@@@@@@@@@@@&&@@@@@@@@@
        #&&&&&&@@@@@@&#BGGP55?J?Y!?Y7!^.~@@@@@@@&G#@@B!5@7@Y Y@@#&@@@@@@@@@@@@@@@@@@@@@@
        #&&&&&@@@#P??~J7?YJY575JY75?7!?^^@@@@&&&&Y!YBB5#@!~^.&@#&@@@@@@@@@@@@@@@@@@@@@@@
        &&&&@@&P~??!~!J?G5JYJ?PJ7JG7!!77!?@@@@@&GJ~:~YG5!:7B7&@#&@@@@@@@@@@@@@@@@@@@@@@@
        &&&@@P:.:JY5~!P7#GYJ75YJ~YB?!7!7Y!?B#&@@@GY7~^~J7^^7!!P&@@@@@@@@@@@@@@@@@@@@@@@@
        &&@@G...J!75?~B?##5??5??~GB?!?~7P77!??PPGB##B5!:^7J55G#@@@@&&@@@@@@@@@@@@@@@@@@@
        &&@#:.:.G?7J7~GJB&G??J7?~BGJ7?~7G7?!^J7?!777J&@BB&@@@@@@@@&#B@@@@@@&&@@@@@@@@@@@
        &@&~.::.5B!5?!Y?B&#J?777~#P?7?~?G???^!P?Y?7!~B#&@@&&&@@@@@@&P@&&@@@&&@@&@@&&@@@@
        &@5..:^.7&~?5P57G&&Y777!!&5???~YBJ?Y!^5G?5Y??B&G&#B#B&&@@@&&#@&#@@@@B&@#@@@&@@@@
        @&::::~.^&!~?B&?G&&P?!!~7&5???~5BJ?5J!^GB?5G5P#B&5BPGB#@@@&&J#@&&@@@#B@&&@@@@@@@
        @Y.~:.^::BJ:~5&JB&&G?7!^?@Y7?7~PGJJY55:!##JY#Y&5G#5JPGB@@@&&?G@&&@@@@G&@#@@@@@@@
        #::!^.:::5P.^?GJB&&BJ7!:J@5777!GPJJY5P^:J&&5GGGBY&?Y555&@@@&PB@&&&@@@##@&@@@&@@@
        ~.^7!:.::7B:.7P?#&&BY7!:J@P!7!7PYYYY?5?:~P@@BGY&5#7JYYY#@@@@#&@@@&@@@@B&&&@&&@@@
        ..~?7~:::~G7.GG~B&&BY7~:J@G!!!?5YYYY!Y5~^?#@@#5#G#77JYJB@@@@&B&&&&@@@@&&@&@&&@@@
        .:~?7!^::^YP:BP^B&&B57~:Y@B!~!J5JJJY!JP!^7P&@@GB##5!7JJP@@@@@GGGYPG#&@@@@&&&@@@@
        .:!J?!~^:^7G~G5^G&&B57~:Y@#7~!5GJ??J!JP?^!YG&@&P&G#77?J5&@@@@#5&5PPY5#&@@@@&@@@@

        SHOUTOUT.TO.RIFKY.THE.CYBER.o0o.The_Gh0stface_Killer.o0o.pL4ce1nv4d3r.o0o.1i1r3d         
              
        ''')
        time.sleep(5)
        os.system("clear")
# Create a regex pattern for all ports in the mapping
def generate_port_pattern(port_list):
    return r'\b(' + '|'.join(map(str, port_list)) + r')\b'

# Function to parse the text file and highlight the ports
def parse_file(filename):
    port_pattern = generate_port_pattern(port_protocol_mapping.keys())

    try:
        with open(filename, 'r') as file:
            unique_entries = {}
            for line in file:
                # Find all matches for ports in the current line
                matches = re.finditer(port_pattern, line)

                # Iterate through matches and print in the desired format
                for match in matches:
                    port = int(match.group())
                    protocols = port_protocol_mapping.get(port, [("Unknown Protocol", 'white')])
                    ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                    if ip_match:
                        ip_address = ip_match.group()
                        key = (ip_address, port)
                        if key not in unique_entries:
                            unique_entries[key] = set()
                        for protocol, _ in protocols:
                            unique_entries[key].add(protocol)

            # Print the unique entries with colorized protocols
            counter = 1
            for (ip_address, port), protocols in unique_entries.items():
                protocol_list = ', '.join(protocols)
                color = port_protocol_mapping[port][0][1] if port in port_protocol_mapping else 'white'
                print(f"{counter}. {ip_address} {port} {colored(protocol_list, color, attrs=['bold'])}")
                counter += 1

            return unique_entries
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

# Function to check for dependencies and download them if needed
def check_and_install_dependencies():
    dependencies = [
        ("ip4scout", "https://github.com/LeakIX/ip4scout/releases/download/v1.0.0-beta.2/ip4scout-linux-64"),
        ("l9filter", "https://github.com/LeakIX/l9filter/releases/download/v1.1.0/l9filter-linux-64")
    ]

    for name, url in dependencies:
        if not shutil.which(name):
            print(colored(f"{name} not found. Downloading...", 'yellow'))
            os.system(f"wget {url}")
            file_name = url.split('/')[-1]
            os.system(f"chmod +x {file_name}")
            os.system(f"sudo mv {file_name} /usr/local/bin/{name}")

# Function to find Telco targets
# Updated find_telco_targets to process outputs asynchronously with color feedback
import threading

# Updated find_telco_targets to allow ending the process by pressing a key
def find_telco_targets():
    command = "sudo ip4scout random --ports=3868,2905,2915,36412,1812,1813,3565,2904,9900,2944,2123,2152 | tee telco-results.json | l9filter transform -i l9 -o human | tee telco-humanreadable.txt"
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    counter = 0
    print(colored("\n[+] Starting target discovery with ip4scout...", 'cyan', attrs=['bold']))

    # Variable to determine if we should stop the process
    stop_process = threading.Event()

    # Function to handle stopping via keypress
    def stop_on_keypress():
        input(colored("\nPress ENTER to stop the target discovery...\n", 'yellow'))
        stop_process.set()
        process.terminate()

    # Run the keypress listener in a separate thread
    keypress_thread = threading.Thread(target=stop_on_keypress)
    keypress_thread.start()

    # Output handling
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_line = {}
        while not stop_process.is_set():
            line = process.stdout.readline().decode('utf-8')
            if not line and process.poll() is not None:
                break
            if line.strip():
                counter += 1
                future_to_line[executor.submit(process_telco_line, line)] = line
                print(colored(f"\r[+] Targets found: {counter}", 'green', attrs=['bold']), end='')

    # Make sure the subprocess is terminated when stopping
    if process.poll() is None:
        process.terminate()
    
    print(colored(f"\n[+] Final count of targets found: {counter}", 'magenta', attrs=['bold']))


# Function to process each line of ip4scout output with color coding
def process_telco_line(line):
    # Any specific processing logic for each line from ip4scout output can be added here.
    # This example returns the line with no modifications.
    print(colored(f"\nProcessing line: {line.strip()}", 'blue'))
    return line

# Function to query Shodan for a specific target
def query_shodan(ip):
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    if not SHODAN_API_KEY:
        print(colored("Error: Shodan API key not found in environment variables.", 'red'))
        return
    api = shodan.Shodan(SHODAN_API_KEY)
    try:
        host = api.host(ip)
        print(colored(f"\n[+] Shodan Data for {ip}:\n", 'yellow', attrs=['bold']))
        print(colored(f"IP: {host['ip_str']}", 'cyan'))
        print(colored(f"Organization: {host.get('org', 'N/A')}", 'cyan'))
        print(colored(f"ISP: {host.get('isp', 'N/A')}", 'cyan'))
        print(colored(f"Country: {host.get('country_name', 'N/A')}", 'cyan'))
        print(colored("Open Ports:", 'cyan'))
        for item in host['data']:
            port = item['port']
            product = item.get('product', 'Unknown')
            print(colored(f"  - Port {port}: {product}", 'magenta'))
    except shodan.APIError as e:
        print(f"Error: {e}")

# Function to run SCTP nmap scan for a target and append results to target entry
def run_sctp_nmap_scan(ip):
    print(colored(f"\n[+] Running SCTP Nmap scan for {ip}...", 'yellow', attrs=['bold']))
    command = f"sudo nmap -sY -p 3868,2905,2915,36412,1812,1813,3565,2904,9900,2944,2123,2152 {ip}"
    result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output = result.stdout.decode('utf-8') if result.stdout else result.stderr.decode('utf-8')
    return ip, output

def run_all_sctp_scans_parallel(unique_entries):
    ips = [ip for (ip, _) in unique_entries.keys()]
    results = {}
    
    print(colored("\n[+] Starting parallel SCTP scans for all targets...", 'cyan', attrs=['bold']))
    with ThreadPoolExecutor(max_workers=5) as executor:  # Adjust `max_workers` based on system capability
        futures = {executor.submit(run_sctp_nmap_scan, ip): ip for ip in ips}
        
        for future in as_completed(futures):
            ip = futures[future]
            try:
                ip, output = future.result()
                print(colored(f"\n[+] SCTP Nmap scan completed for {ip}", 'green'))
                print(colored(output, 'cyan'))  # Print the scan results in cyan for clarity
                results[ip] = output
            except Exception as e:
                print(colored(f"Error scanning {ip}: {e}", 'red', attrs=['bold']))

    print(colored("\n[+] All parallel SCTP scans completed.", 'magenta', attrs=['bold']))
    return results

# Function to save entries to CSV
def save_entries_to_csv(unique_entries, indices=None):
    csv_filename = input(colored("Enter the filename (with .csv extension): ", 'cyan'))
    try:
        with open(csv_filename, 'w') as csv_file:
            csv_file.write("IP,Port,Protocols,Nmap Scan Result\n")
            for index, ((ip_address, port), protocols) in enumerate(unique_entries.items()):
                if indices is None or index in indices:
                    protocol_list = ', '.join(protocols)
                    nmap_scan_result = unique_entries.get((ip_address, port), {}).get("nmap_scan_result", "None")
                    csv_file.write(f"{ip_address},{port},{protocol_list},{nmap_scan_result}\n")
        print(colored(f"Output successfully saved to {csv_filename}", 'green'))
    except Exception as e:
        print(colored(f"An error occurred while saving the file: {e}", 'red'))

# Main menu for CLI interaction
def main_menu():
    ascii_banner()
    banner = pyfiglet.figlet_format("Telco Finder",font="slant")
    print(colored(banner, 'cyan'))
    while True:
        print(colored("\nMain Menu:", 'magenta', attrs=['bold']))
        print(colored("1. Check and Install Dependencies (ip4scout and l9filter)", 'yellow'))
        print(colored("2. Find Telco Targets", 'yellow'))
        print(colored("3. Parse Telco Target Data with Highlighting", 'yellow'))
        print(colored("4. Query Shodan for a Target", 'yellow'))
        print(colored("5. Run SCTP Nmap Scan for a Target", 'yellow'))
        print(colored("6. Run SCTP Nmap Scan for All Targets", 'yellow'))
        print(colored("7. Save Parsed Data to CSV", 'yellow'))
        print(colored("8. Exit", 'yellow'))
        choice = input(colored("Enter your choice: ", 'cyan'))

        if choice == "1":
            check_and_install_dependencies()
        elif choice == "2":
            find_telco_targets()
        elif choice == "3":
            unique_entries = parse_file("telco-humanreadable.txt")
        elif choice == "4":
            unique_entries = parse_file("telco-humanreadable.txt")
            target_index = int(input(colored("\nEnter the index number of the target to query Shodan for: ", 'cyan')))
            target_list = list(unique_entries.keys())
            if 1 <= target_index <= len(target_list):
                ip, _ = target_list[target_index - 1]
                query_shodan(ip)
            else:
                print(colored("Invalid index number.", 'red'))
        elif choice == "5":
            unique_entries = parse_file("telco-humanreadable.txt")
            target_index = int(input(colored("\nEnter the index number of the target to run SCTP Nmap scan for: ", 'cyan')))
            target_list = list(unique_entries.keys())
            if 1 <= target_index <= len(target_list):
                ip, _ = target_list[target_index - 1]
                run_sctp_nmap_scan(ip, unique_entries, target_index - 1)
            else:
                print(colored("Invalid index number.", 'red'))
        elif choice == "6":
            unique_entries = parse_file("telco-humanreadable.txt")
            for index, (ip, _) in enumerate(unique_entries.keys()):
                run_sctp_nmap_scan(ip, unique_entries, index)
        elif choice == "7":
            unique_entries = parse_file("telco-humanreadable.txt")
            save_type = input(colored("\nSave options: 1. Save individual record, 2. Save multiple records, 3. Save all records. Enter your choice: ", 'cyan'))
            if save_type == "1":
                record_index = int(input(colored("Enter the index number of the record to save: ", 'cyan'))) - 1
                save_entries_to_csv(unique_entries, indices=[record_index])
            elif save_type == "2":
                record_indices = input(colored("Enter the index numbers separated by commas (e.g., 1,3,5): ", 'cyan'))
                indices = [int(i.strip()) - 1 for i in record_indices.split(',')]
                save_entries_to_csv(unique_entries, indices=indices)
            elif save_type == "3":
                save_entries_to_csv(unique_entries)
            else:
                print(colored("Invalid choice.", 'red'))
        elif choice == "8":
            print(colored("Exiting application.", 'red'))
            break
        else:
            print(colored("Invalid choice. Please select a valid option.", 'red'))

if __name__ == "__main__":
    main_menu()
