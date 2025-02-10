import sqlite3
import requests
import urllib3
import json
from requests.auth import HTTPBasicAuth
import re
import ast
from enum import Enum
import google.generativeai as genai
import os
from dotenv import load_dotenv


load_dotenv()
api_key = os.getenv("GENAI_API_KEY")
genai.configure(api_key=api_key)
model = genai.GenerativeModel("gemini-1.5-flash")

urllib3.disable_warnings()

templates = {}
url = "/restconf/data/"

class HttpStatus(Enum):
    # 1xx Informational
    CONTINUE = 100
    SWITCHING_PROTOCOLS = 101
    PROCESSING = 102

    # 2xx Success
    OK = 200
    CREATED = 201
    ACCEPTED = 202
    NON_AUTHORITATIVE_INFORMATION = 203
    NO_CONTENT = 204
    RESET_CONTENT = 205
    PARTIAL_CONTENT = 206

    # 3xx Redirection
    MULTIPLE_CHOICES = 300
    MOVED_PERMANENTLY = 301
    FOUND = 302
    SEE_OTHER = 303
    NOT_MODIFIED = 304
    USE_PROXY = 305
    TEMPORARY_REDIRECT = 307

    # 4xx Client Error
    BAD_REQUEST = 400
    UNAUTHORIZED = 401
    PAYMENT_REQUIRED = 402
    FORBIDDEN = 403
    NOT_FOUND = 404
    METHOD_NOT_ALLOWED = 405
    NOT_ACCEPTABLE = 406
    PROXY_AUTHENTICATION_REQUIRED = 407
    REQUEST_TIMEOUT = 408
    CONFLICT = 409

    # 5xx Server Error
    INTERNAL_SERVER_ERROR = 500
    NOT_IMPLEMENTED = 501
    BAD_GATEWAY = 502
    SERVICE_UNAVAILABLE = 503
    GATEWAY_TIMEOUT = 504
    HTTP_VERSION_NOT_SUPPORTED = 505


def init_db():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS devices
                      (name TEXT, ip TEXT, username TEXT, password TEXT)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS templates
                    (name TEXT PRIMARY KEY, config TEXT)''')
    
    conn.commit()
    conn.close()

def add_device():
    name = input("Enter device name: ")
    ip = input("Enter device IP: ")
    username = input("Enter username: ")
    password = input("Enter password: ")

    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute("INSERT INTO devices (name, ip, username, password) VALUES (?, ?, ?, ?)",
                   (name, ip, username, password))
    conn.commit()
    conn.close()
    print(f"Device {name} added successfully!")

def add_template(name, config):

    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO templates (name, config) VALUES (?, ?)", (name, config))
        conn.commit()
        print(f"Template {name} added to the database successfully!")
    except sqlite3.IntegrityError:
        print(f"Template {name} already exists. Please use a unique name.")
    conn.close()

def remove_device():
    devices = get_devices()
    if not devices:
        print("No devices available to remove.")
        return

    print("\nSelect a device to remove:")
    for idx, device in enumerate(devices, start=1):
        print(f"{idx}- {device['name']}")
    choice = int(input("Enter device number: "))

    if choice < 1 or choice > len(devices):
        print("Invalid choice.")
        return

    device = devices[choice - 1]

    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE name = ?", (device['name'],))
    conn.commit()
    conn.close()
    print(f"Device {device['name']} removed successfully!")

def delete_template(name):
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM templates WHERE name = ?", (name,))
    if cursor.rowcount > 0:
        print(f"Template {name} deleted successfully!")
    else:
        print(f"Template {name} not found.")
    conn.commit()
    conn.close()

def get_devices():
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices")
    devices = [{"name": row[0], "ip": row[1], "username": row[2], "password": row[3]} for row in cursor.fetchall()]
    conn.close()
    return devices

def get_templates():
    """Retrieve all templates from the database as a dictionary."""
    conn = sqlite3.connect('devices.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, config FROM templates")
    rows = cursor.fetchall()
    conn.close()

    # Convert the result to a dictionary
    templates = {name: config for name, config in rows}
    return templates


def show_devices():
    devices = get_devices()
    if not devices:
        print("No devices available.")
        return

    print("\nConfigured Devices:")
    for device in devices:
        print(f"Name: {device['name']}, IP: {device['ip']}, Username: {device['username']}, Password: {device['password']}")

# Done
def select_device():
    devices = get_devices()
    if not devices:
        print("No devices available. Add a device first.")
        return None

    while True:
        print("\nSelect a device:")
        for idx, device in enumerate(devices, start=1):
            print(f"{idx}- {device['name']}")
        print("0- All devices")
        choice = int(input("Enter device number: "))

        if choice == 0:
            return devices
        elif 1 <= choice <= len(devices):
            return [devices[choice - 1]]
        else:
            print("\nInvalid choice, try again!")

# Done 
def api_call(url, payload, http_method, devices):
    headers = {
        'Content-Type': 'application/yang-data+json',
        'Accept': 'application/yang-data+json'
    }

    responses = []
    for device in devices:
        print(f"\nConnecting to {device['name']} ({device['ip']})...")
        full_url = f"https://{device['ip']}{url}"
        try:
            if http_method.upper() == "GET":
                response = requests.get(full_url, auth=HTTPBasicAuth(device['username'], device['password']), headers=headers, verify=False)
            elif http_method.upper() == "POST":
                response = requests.post(full_url, auth=HTTPBasicAuth(device['username'], device['password']), headers=headers, data=json.dumps(payload), verify=False)
            elif http_method.upper() == "PATCH":
                response = requests.patch(full_url, auth=HTTPBasicAuth(device['username'], device['password']), headers=headers, data=json.dumps(payload), verify=False)
            elif http_method.upper() == "DELETE":
                response = requests.delete(full_url, auth=HTTPBasicAuth(device['username'], device['password']), headers=headers, verify=False)
            else:
                print(f"Invalid HTTP method: {http_method}")
                responses.append(None)
                continue
            responses.append({
                "device": device['name'],
                "ip": device['ip'],
                "status": str(response.status_code),
                "response": response,
                "error": None
            })
           
        except requests.exceptions.RequestException as e:
            print(f"Error connecting to {device['name']}: {str(e)}")
            responses.append({
                "device": device['name'],
                "ip": device['ip'],
                "status": None,
                "response": None,
                "error": str(e)
            })
    return responses
    
# Done
def monitor_menu():
    while True:
        print("\nSelect what to monitor: ")
        print("1- CPU Utilization")
        print("2- Memory Utilization")
        print("3- Version")
        print("4- Environmental Details")
        print("5- Call-Home Profiles")
        print("6- VRF")
        print("7- interface")
        print("0- return to main menu")
        choice = int(input("Enter your choice: ").strip())
        if 1 <= choice <= 7:
            device = select_device()
        
        match choice:
            case 1:
                fetch_CPU_Usage(device)
            case 2:
                fetch_Memory_Usage(device)
            case 3:
                fetch_version(device)
            case 4:
                fetch_environmental_details(device)
            case 5:
                fetch_call_home_profiles(device)
            case 6:
                fetch_vrfs(device)
            case 7:
                fetch_interfaces(device)
            case 0:
                break
            case _:
                print("\nInvalid choice, try again!")

# Done
def handle_configuration():
    while True:
        print("\nSelect type of configuration:")
        print("1- Configuration Automation - Templates")
        print("2- Configure a specific device")
        print("0- Back to main menu")
        choice = int(input("Enter your choice: ").strip())

        match choice:
            case 1:
                configuration_templates_menu()
            case 2:
                devices_list = select_device()
                if len(devices_list) == 1:
                    configuration_menu(devices_list)
                else:
                    print("Invalid choice.")
            case 0:
                break
            case _:
                print("\nInvalid choice, try again!")


# Done
def configuration_menu(device):
    while True:
        print("\nSelect what to configure: ")
        print("1- Configure banner")
        print("2- Configure ACL")
        print("3- configure Call-home")
        print("4- configure NTP")
        print("5- configure SNMP hosts")
        print("6- configure VRF")
        print("0- Return Back")
        choice = int(input("Enter your choice: ").strip())

        match choice:
            case 1:
                configure_banner(device)
            case 2:
                configure_ACL(device)
            case 3:
                configure_call_home(device)
            case 4:
                configure_ntp(device)
            case 5:
                configure_snmp(device)
            case 6:
                configure_vrf(device)
            case 0:
                break
            case _:
                print("\nInvalid choice, try again!")

# Done
def configuration_templates_menu():
    while True:
        print("\nTemplates options:")
        print("1- Manage Templates")
        print("2- Use a template")
        print("0- Back to previous menu")
        choice = int(input("Enter your choice: ").strip())

        match choice:
            case 1:
                manage_templates()
            case 2:
                use_template()
            case 0:
                break
            case _:
                print("\nInvalid choice, try again!")

# Done
def manage_devices_menu():
    while True:
        print("\nManage Devices:")
        print("1- Add a device")
        print("2- Remove a device")
        print("3- Show configured devices")
        print("0- Back to main menu")
        choice = int(input("Enter your choice: "))

        match choice:
            case 1:
                add_device()
            case 2:
                remove_device()
            case 3:
                show_devices()
            case 0:
                break
            case _:
                print("\nInvalid choice, try again!")

# Done       
def troubleshooting_menu():
    while True:
        print("\nSelect what to troubleshoot: ")
        print("1- Troubleshoot CPU Utilization")
        print("2- Troubleshoot Memory Utilization")
        print("3- Troubleshoot Environmental Parameters")
        print("4- Troubleshoot Interfaces")
        print("5- Troubleshoot BGP")
        print("6- Troubleshoot OSPF")
        print("0- return to main menu")
        choice = int(input("Enter your choice: "))
        if 1 <= choice <= 6:
            device = select_device()

        match choice:
            case 1:
                troubleshoot_CPU_AI(device)
            case 2:
                troubleshoot_memory_AI(device)
            case 3:
                troubleshoot_environment_AI(device)
            case 4:
                troubleshoot_interfaces_AI(device)
            case 5:
                troubleshoot_BGP_AI(device)
            case 6:
                troubleshoot_OSPF_AI(device)
            case 0:
                break
            case _:
                print("\nInvalid choice, try again!")

# Done
def manage_templates():
    """
    Menu for managing templates, including creating and deleting templates.
    """
    while True:
        print("\nTemplate Management:")
        print("1- Create a template")
        print("2- Delete a template")
        print("0- Back to previous menu")
        choice = input("Enter your choice: ").strip()

        if choice == "1":
            create_template()
        elif choice == "2":
            delete_template()
        elif choice == "0":
            break
        else:
            print("\nInvalid choice, yry again!")

# Done
def template_name_validator():
    while True:
        name = input("Enter the name of the template: ").strip()
        templateKeys = templates.keys()
        TemplateName = [key.split(": ")[1] for key in templateKeys if ": " in key]
        if name in TemplateName:
            print(f"{name} already exists, try again!")
        else:
            return name

# Done
def create_template():
    while True:
        """Allows the user to create a configuration template."""
        print("\nCreate a template for:")
        print("1- VRF template")
        print("2- Access list template")
        print("3- SNMP host template")
        print("4- Call-home template")
        print("5- NTP template")
        print("6- Banner template")
        print("0- Return to previous menu")    
        template_choice = int(input("Select the template you want to create: ").strip())
        if template_choice < 1 | template_choice > 6:
            print("\nInvalid choice, try again!")
            continue
        elif template_choice == 0:
            return
        template_name = template_name_validator()

        try:
            match template_choice:
                case 1:
                    templates["VRF: " + template_name] = VRF_template()
                case 2:
                    templates["ACL: " + template_name] = ACL_template()
                case 3:
                    templates["SNMP: " + template_name] = snmp_host_template()
                case 4:
                    templates["CALL-HOME: " + template_name] = Call_home_template()
                case 5:
                    templates["NTP: " + template_name] = ntp_template()
                case 6:
                    templates["BANNER: " + template_name] = banner_template()
                case _:
                    print("Invalid choice.")
                    return

            print(f"Template '{template_name}' created successfully!")
            add_template(list(templates.keys())[-1], str(templates[list(templates.keys())[-1]]))
        except Exception as e:
            print(f"Error creating template: {e}")

# Done
def delete_template():
    """Allows the user to delete an existing configuration template."""
    if not templates:
        print("No templates available. Create a template first.")
        return
    print("\nExisting templates:")
    for idx, template in enumerate(templates.keys(), start=1):
        print(f"{idx}- {template}")
    print("0- back to the previous menu")

    try:
        template_choice = int(input("Select a template to delete: ").strip())
        if 1 <= template_choice <= len(templates):
            template_name = list(templates.keys())[template_choice - 1]
            templates.pop(template_name)
            delete_template(template_name)
            print(f"Template '{template_name}' deleted successfully!")
        elif template_choice == 0:
            return
        else:
            print("Invalid choice.")
    except ValueError:
        print("Please enter a valid number.")
# Done
def use_template():
    """Allows the user to use an existing configuration template."""
    if not templates:
        print("No templates available. Create a template first.")
        return

    print("\nExisting templates:")
    for idx, template in enumerate(templates.keys(), start=1):
        print(f"{idx}- {template}")

    try:
        template_choice = int(input("Select a template to use: ").strip())
        if 1 <= template_choice <= len(templates):
            template_name = list(templates.keys())[template_choice - 1]
            payLoad = ast.literal_eval(templates[template_name])
            print(payLoad)
            devices_list = select_device()
            if not devices_list:
                print("No devices selected. Operation aborted.")
                return
            
            print(f"Applying template '{template_name}' to the following devices:")
            temp_type = str(template_name).split(":")[0]
            match temp_type:
                case "VRF":
                    configure_vrf(devices_list, payLoad)
                case "ACL":
                    configure_ACL(devices_list, payLoad)
                case "SNMP":
                    configure_snmp(devices_list, payLoad)
                case "CALL-HOME":
                    configure_call_home(devices_list, payLoad)
                case "NTP":
                    configure_ntp(devices_list, payLoad)
                case "BANNER":
                    configure_banner(devices_list, payLoad)
                case _:
                    print("error in the template - unrecognized template type")
        else:
            print("Invalid choice.")
    except ValueError:
        print("Please enter a valid number." )


# Done
def fetch_CPU_Usage(device):
    endpoint = "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization/one-minute"
    responses = api_call(url + endpoint, None, "GET", device)

    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print ("Status: " + response['status']+ "\n")
        if response['error']:
            print(f"Error: {response['error']}")
            continue
            
        try:
            cpu_usage = re.search(r'"Cisco-IOS-XE-process-cpu-oper:one-minute":\s*(\d+)', response['response'].text)
            print(f"CPU Usage (1min): {cpu_usage.group(1)}%")
        except json.JSONDecodeError:
            print("Invalid JSON response")
        except KeyError:
            print("Unexpected response format")
# Done
def fetch_Memory_Usage(device):
    endpoint = "Cisco-IOS-XE-memory-oper:memory-statistics/memory-statistic"

    responses = api_call(url + endpoint, None, "GET", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        if response['error']:
            print(f"Error: {response['error']}")
            continue
        try:
            header = ["Head", "Total(b)", "Used(b)", "Free(b)", "Lowest(b)", "Largest(b)"]
            column_widths = [22, 12, 12, 12, 12, 12]
            print("".join(h.ljust(w) for h, w in zip(header, column_widths)))
            for stat in response['response'].json()["Cisco-IOS-XE-memory-oper:memory-statistic"]:
                name = stat["name"]
                total = stat["total-memory"]
                used = stat["used-memory"]
                free = stat["free-memory"]
                lowest = stat["lowest-usage"]
                highest = stat["highest-usage"]
                
                # Format the row and print
                row = [
                    name.ljust(18),
                    total.rjust(12),
                    used.rjust(12),
                    free.rjust(12),
                    lowest.rjust(12),
                    highest.rjust(12),
                ]
                print("".join(row))
        except json.JSONDecodeError:
            print("Invalid JSON response")
        except KeyError:
            print("Unexpected response format")
# Done    
def fetch_version(device):
    endpoint = "Cisco-IOS-XE-native:native/version"

    responses = api_call(url + endpoint, None, "GET", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'])
        if response['error']:
            print(f"Error: {response['error']}")
            continue
        try:
            version = response['response'].json()["Cisco-IOS-XE-native:version"]
            print(f"The running version is {version}")
        except json.JSONDecodeError:
            print("Invalid JSON response")
        except KeyError:
            print("Unexpected response format")
# Done
def fetch_environmental_details(device):
    endpoint = "Cisco-IOS-XE-environment-oper:environment-sensors/environment-sensor"  

    responses = api_call(url + endpoint, None, "GET", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'])
        if response['error']:
            print(f"Error: {response['error']}")
            continue
        try:
            print(f"+{'-' * 28}+{'-' * 12}+{'-' * 17}+{'-' * 27}+")
            print(f"| {'Name + Sensor':<26} | {'Location':<10} | {'State':<15} | {'Current Reading':<25} |")
            print(f"+{'-' * 28}+{'-' * 12}+{'-' * 17}+{'-' * 27}+")
            
            # Loop through the JSON data and print each row
            for item in response['response'].json()["Cisco-IOS-XE-environment-oper:environment-sensor"]:
                name_sensor = f"{item['name']} {item['sensor-name']}"
                location = item["location"]
                state = item["state"]
                reading_units = f"{item['current-reading']} {item['sensor-units']}"
                
                print(f"| {name_sensor:<26} | {location:<10} | {state:<15} | {reading_units:<25} |")
            
            print(f"+{'-' * 28}+{'-' * 12}+{'-' * 17}+{'-' * 27}+")

        except json.JSONDecodeError:
            print("Invalid JSON response")
        except KeyError:
            print("Unexpected response format")
# Done
def fetch_call_home_profiles(device):
    endpoint = "Cisco-IOS-XE-native:native/call-home/Cisco-IOS-XE-call-home:profile"

    responses = api_call(url + endpoint, None, "GET", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'])
        if response['error']:
            print(f"Error: {response['error']}")
            continue
        try:
            print(response['response'].text)
        except json.JSONDecodeError:
            print("Invalid JSON response")
        except KeyError:
            print("Unexpected response format")
# Done
def fetch_vrfs(device):
    endpoint = "Cisco-IOS-XE-native:native/ip/vrf"

    responses = api_call(url + endpoint, None, "GET", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'])
        if response['error']:
            print(f"Error: {response['error']}")
            continue
        try:
            print(response['response'].text)
        except json.JSONDecodeError:
            print("Invalid JSON response")
        except KeyError:
            print("Unexpected response format")
# Done
def fetch_interfaces(device):  
    """Allows the user to select the interface type."""
    interfaceTypes = ["GigabitEthernet", "TenGigabitEthernet", "HundredGigE", "Loopback"]
    print("1- GigabitEthernet")
    print("2- TenGigabitEthernet")
    print("3- HundredGigE")
    print("4- Loopback") 
    UserInterfaceType = int(input("Select the interface type: ").strip())
    interfaceNumber = input("Select the interface number: ").strip()
    interface = f"{interfaceTypes[UserInterfaceType - 1]}={interfaceNumber}"
    
    endpoint = f"Cisco-IOS-XE-native:native/interface/{interface}"

    responses = api_call(url + endpoint, None, "GET", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print ("Status: " + response['status'])
        print(response['response'].text)



# Done all templates
def VRF_template():
    name = input("VRF Name: ")
    description = input("VRF Description: ")
    rd = input("Route Distinguisher (##:##): ")
    
    # Initialize route-target list
    route_targets = []

    add_rt = input("Do you want to add route-targets? (yes/no): ").strip().lower()
    
    if add_rt == "yes":
        # Add import route targets
        add_import = input("Do you want to add import route-targets? (yes/no): ").strip().lower()
        while add_import == "yes":
            rt_import = input("Enter Route Target - Import (##:##): ")
            route_targets.append({
                "direction": "import",
                "target": rt_import
            })
            add_import = input("Add another import route-target? (yes/no): ").strip().lower()
        
        # Add export route targets
        add_export = input("Do you want to add export route-targets? (yes/no): ").strip().lower()
        while add_export == "yes":
            rt_export = input("Enter Route Target - Export (##:##): ")
            route_targets.append({
                "direction": "export",
                "target": rt_export
            })
            add_export = input("Add another export route-target? (yes/no): ").strip().lower()

    # Build the payload
    payLoad = {
        "vrf": [
            {
                "name": name,
                "description": description,
                "rd": rd,
                "route-target": route_targets if route_targets else None
            }
        ]
    }

    # Remove the route-target key if no route targets were added
    if not route_targets:
        del payLoad["vrf"][0]["route-target"]
    
    return payLoad

def ACL_template():

    name = input("ACL name: ")
    seq = input("Sequence: ")
    action = input("Action: ")
    protocol = input("Protocol: ")
    src_ip = input("Source IP: ")
    src_w_mask = input("Wilemask: ")
    dst_ip = input("Destination IP: ")
    dst_w_mask = input("Wilemask: ")
    dst_port = input("Destination port: ")

    payLoad = {
        "extended": [
            {
            "name": f"{name}",
            "access-list-seq-rule": [
                {
                f"sequence": int(seq),
                "ace-rule": {
                    "action": f"{action}",
                    "protocol": f"{protocol}",
                    "ipv4-address": f"{src_ip}",
                    "mask": f"{src_w_mask}",
                    "dest-ipv4-address": f"{dst_ip}",
                    "dest-mask": f"{dst_w_mask}",
                    "dst-eq": f"{dst_port}"
                }
                }
            ]
            }
        ]
    }

    return payLoad

def ntp_template():
    ip = input("NTP SERVER IP: ")
    version = input("NTP VERSION: ")
    key = input("KEY NUMBER: ")
    payLoad = {
        "server-list": {
            "ip-address": f"{ip}",
            "version": f"{version}",
            "key": f"{key}"
        }
    }

    return payLoad

def snmp_host_template():
    ip = input("HOST IP: ")
    version = input("VERSION: ")
    community = input("HOST COMMUNITY STRING: ")

    payLoad = {
        "host": [
            {
            "ip-address": f"{ip}",
            "version": f"{version}",
            "community-or-user": f"{community}"
            }
        ]
    }

    return payLoad

def Call_home_template():
    profile_name = input("Profile name: ")
    email = input("Email address: ")
    destination_address = input("Destination address: ")
    
    payLoad = {
        "Cisco-IOS-XE-call-home:profile": {
            "profile-name": f"{profile_name}",
            "active": True,
            "destination": {
                "transport-method": "http",
                "address": {
                    "email": f"{email}",
                    "http": f"{destination_address}"
                }
            }
        }
    }
    return payLoad

def banner_template():
    print("1- exec\n2- login\n3- prompt-timeout\n4- motd")
    banner_types = ["exec", "login", "prompt-timeout", "motd"]
    banner_choice = int(input("Select banner type: "))

    message = input("Enter banner message: ")

    payLoad= {
        "banner": {
            f"{banner_types[banner_choice-1]}": {
                "banner": f"c{message}c"
            }
        }
    }    
    return payLoad

# Done all conf functions
def configure_banner(device, payLoad=None):
    endpoint = "Cisco-IOS-XE-native:native/banner"

    if payLoad == None:
        payLoad= banner_template()

    responses = api_call(url + endpoint, payLoad, "PATCH", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        print(response['response'].text)

def configure_ACL(device, payload):
    endpoint = "Cisco-IOS-XE-native:native/ip/access-list/Cisco-IOS-XE-acl:extended"

    if payload == None:
        payload = ACL_template()

    responses = api_call(url + endpoint, payload, "PATCH", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        print(response['response'].text)

def configure_vrf(device, payload = None):
    endpoint = "Cisco-IOS-XE-native:native/ip/vrf"
    
    if payload == None:
        payload = VRF_template()

    responses = api_call(url + endpoint, payload, "PATCH", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        print(response['response'].text)

def configure_ntp(device, payload):
    endpoint = "Cisco-IOS-XE-native:native/ntp/Cisco-IOS-XE-ntp:server/server-list"
    
    if payload == None:
        payload = ntp_template()

    responses = api_call(url + endpoint, payload, "PATCH", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        print(response['response'].text)

def configure_snmp(device, payload):
    endpoint = "Cisco-IOS-XE-native:native/snmp-server/Cisco-IOS-XE-snmp:host"

    if payload == None:
        payload = snmp_host_template()

    responses = api_call(url + endpoint, payload, "PATCH", device)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        print(response['response'].text)

def configure_call_home(devices, payload):
    endpoint = "Cisco-IOS-XE-native:native/call-home/Cisco-IOS-XE-call-home:profile"

    if payload == None:
        payload = Call_home_template()

    responses = api_call(url + endpoint, payload, "PATCH", devices)
    for response in responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        print (response['status'] + "\n")
        print(response['response'].text)


def troubleshoot_CPU_AI(device):
    endpoint = "Cisco-IOS-XE-process-cpu-oper:cpu-usage/cpu-utilization/one-minute"
    
    API_responses = api_call(url + endpoint, None, "GET", device)
    prompt = "This is an output from IOS-XE router for CPU Utilization. Analyze it and give a short troubleshooting steps if there was a problem. the output: "
    for response in API_responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        code = int(response['status'])
        print(HttpStatus(code))
        if code == 200:
            print("GenAI analysis is: \n\n\n")
            AI_response = model.generate_content(prompt + response['response'].text)
            print(AI_response.text)
        else:
            print (code + "\n" + response['response'].text)

def troubleshoot_memory_AI(device):
    endpoint = "Cisco-IOS-XE-memory-oper:memory-statistics/memory-statistic"

    API_responses = api_call(url + endpoint, None, "GET", device)
    prompt = "This is an output from IOS-XE router for Memory Utilization. Analyze it and give a short troubleshooting steps if there was a problem. the output: "
    for response in API_responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        code = int(response['status'])
        print(HttpStatus(code))
        if code == 200:
            print("GenAI analysis is: \n\n\n")
            AI_response = model.generate_content(prompt + response['response'].text)
            print(AI_response.text)
        else:
            print (code + "\n" + response['response'].text)

def troubleshoot_environment_AI(device):
    endpoint = "Cisco-IOS-XE-environment-oper:environment-sensors/environment-sensor"  

    API_responses = api_call(url + endpoint, None, "GET", device)
    prompt = "This is an output from IOS-XE router for Environmental variables. Analyze it and give a short troubleshooting steps if there was a problem. the output:"
    for response in API_responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        code = int(response['status'])
        print(HttpStatus(code))
        if code == 200:
            print("GenAI analysis is: \n\n\n")
            AI_response = model.generate_content(prompt + response['response'].text)
            print(AI_response.text)
        else:
            print (code + "\n" + response['response'].text)

def troubleshoot_BGP_AI(device):
    endpoint = "Cisco-IOS-XE-bgp-oper:bgp-state-data"

    API_responses = api_call(url + endpoint, None, "GET", device)
    prompt = "This is an output from IOS-XE router for BGP. Analyze it and give a short troubleshooting steps if there was a problem. the output: "
    for response in API_responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        code = int(response['status'])
        print(HttpStatus(code))
        if code == 200:
            print("GenAI analysis is: \n\n\n")
            AI_response = model.generate_content(prompt + response['response'].text)
            print(AI_response.text)
        else:
            print (code + "\n" + response['response'].text)

def troubleshoot_OSPF_AI(device):
    endpoint = "Cisco-IOS-XE-ospf-oper:ospf-oper-data"

    API_responses = api_call(url + endpoint, None, "GET", device)
    prompt = "This is an output from IOS-XE router for OSPF. Analyze it and give a short troubleshooting steps if there was a problem. the output: "
    for response in API_responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        code = int(response['status'])
        print(HttpStatus(code))
        if code == 200:
            print("GenAI analysis is: \n\n\n")
            AI_response = model.generate_content(prompt + response['response'].text)
            print(AI_response.text)
        else:
            print (code + "\n" + response['response'].text)

def troubleshoot_interfaces_AI(device):
    endpoint = "Cisco-IOS-XE-interfaces-oper:interfaces/interface"

    API_responses = api_call(url + endpoint, None, "GET", device)
    prompt = "This is an output from IOS-XE router for OSPF. Analyze it and give a short troubleshooting steps if there was a problem. the output: "
    for response in API_responses:
        print(f"\nDevice: {response['device']} ({response['ip']})")
        code = int(response['status'])
        print(HttpStatus(code))
        if code == 200:
            print("GenAI analysis is: \n\n\n")
            AI_response = model.generate_content(prompt + response['response'].text)
            print(AI_response.text)
        else:
            print (code + "\n" + response['response'].text)
 
def main_menu():
    while True:
        print("\nWelcome to the Network Automation and Configuration Management System:")
        print("1- Monitor devices")
        print("2- Configure devices")
        print("3- Troubleshoot using AI")
        print("4- Manage devices")
        print("0- Exit")
        choice = input("Enter your choice: ")


        match choice:
            case "1":
                monitor_menu()
            case "2":
                handle_configuration()
            case "3":
                troubleshooting_menu()
            case "4":
                manage_devices_menu()
            case "0":
                break
            case _:
                print("Invalid choice. Try again.")

if __name__ == "__main__":
    init_db()
    templates = get_templates()
    main_menu()
