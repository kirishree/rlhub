import serial
import time
from serial.tools import list_ports
import json
import requests
import getpass
import re
urllogin = "https://reachlinktest.cloudetel.com/beapi/auth"
url = "https://reachlinktest.cloudetel.com/beapi/get_ciscospoke_config"
def find_com_port(description=None):
    """
    Automatically find the COM port to which the Cisco router is connected.
    :param description: Part of the device description to search for (optional).
    :return: The COM port if found, else None.
    """
    ports = list_ports.comports()
    for port in ports:
        if description:
            if description.lower() in port.description.lower():
                print(f"Device found on {port.device}: {port.description}")
                return port.device
        else:
            print(f"Available port: {port.device}")
            return port.device
    return None

def connect_to_router(com_port, baud_rate=9600):
    """
    Establish a serial connection to the router.
    :param com_port: The COM port to connect to.
    :param baud_rate: The baud rate for the serial connection.
    :return: The serial connection object.
    """
    try:
        ser = serial.Serial(com_port, baud_rate, timeout=1)
        print(f"Connected to {com_port} at {baud_rate} baud.")
        return ser
    except serial.SerialException as e:
        print(f"Error connecting to {com_port}: {e}")
        return None

def send_commands(ser, commands):
    """
    Send configuration commands to the router.
    :param ser: The serial connection object.
    :param commands: A list of commands to send.
    """
    for cmd in commands:
        ser.write((cmd + '\n').encode('utf-8'))
        time.sleep(2)  # Give the router time to process the command
        output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
        print(f"Router output: {output}")

def send_commands_rsa(ser, commands):
    """
    Send configuration commands to the router and handle RSA key generation interactively.
    :param ser: The serial connection object.
    :param commands: A list of commands to send (e.g., "crypto key generate rsa").
    """
    for cmd in commands:
        ser.write((cmd + '\n').encode('utf-8'))
        time.sleep(3)  # Give the router time to process the command
        
        # Read output after sending the command
        output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
        print(f"Router output: {output}")

       
        ser.write("yes\n".encode('utf-8'))
        time.sleep(3)  # Wait for router to process the response
        output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
        print(f"Router output after 'yes': {output}")

        
        ser.write("2048\n".encode('utf-8'))
        time.sleep(3)  # Wait for router to process the response
        output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
        print(f"Router output after key size: {output}")

        # Check for RSA key generation confirmation
        if "Generating RSA keys" in output:
            print("RSA key generation in progress...")
   
def is_valid_email(email):
    """Validate email format."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

def main():    
    while True:
        username = input("Enter the Registered username with ReachLink\nUsername (Mail ID): ")
        if is_valid_email(username):
            break  # Exit the loop if email is valid
        else:
            print("❌ Invalid email format. Please enter a valid email.")
    print(f"Enter the password of {username}:")
    password = getpass.getpass() 
    print(f"Enter the registered Branch location:")
    branch_location = input()    
    branch_loc = branch_location.lower()    
    headers = {"Content-Type": "application/json"}
    authinfo = json.dumps({"username": username,"password": password})
    try:
        authresponse = requests.post(urllogin, data= authinfo, headers= headers)
        authresponse.raise_for_status()
        if authresponse.status_code == 200:           
            json_authresponse = authresponse.text.replace("'", "\"")  # Replace single quotes with double quotes
            json_authresponse = json.loads(json_authresponse)
            if "access" not in json_authresponse:
                print(json_authresponse["message"])  
                print("Enter a key to exit...")
                input()
                return
            else:
                access_token = json_authresponse["access"]
        else:
            print("Error while authenticating data")
            print("Enter a key to exit...")
            input()
            return
    except Exception as e:
        print(f"Error while getting configuration: {e}")
        print("Enter a key to exit...")
        input()
        return    
    # Set the headers to indicate that you are sending JSON data
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {access_token}"}
    userinfo = {"username": username,
                "password": password,
                "branch_loc": branch_loc,
                "ciscohub": "cisco_ubuntu"} 
    json_data = json.dumps(userinfo)
    try:
        response = requests.post(url, data=json_data, headers=headers)  # Timeout set to 5 seconds
        response.raise_for_status()
        if response.status_code == 200:           
            json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
            json_response = json.loads(json_response)
            if  "This device is already Registered" not in json_response["message"]:
                print(json_response["message"])  
                print("Enter a key to exit...")
                input()
                return        
        else:
            print("Error while authenticating data")
            print("Enter a key to exit...")
            input()
            return
    except Exception as e:
        print(f"Error while getting configuration: {e}")
        print("Enter a key to exit...")
        input()
        return
    # Step 1: Identify the COM port
    target_description = "USB-to-Serial"
    com_port = find_com_port(target_description)
    if not com_port:
        print("No Cisco router found. Please check the connection.")
        print("Enter a key to exit...")
        input()
        return

    # Step 2: Connect to the router
    ser = connect_to_router(com_port)
    if not ser:
        print("Connection failed. Pl try again.")
        print("Enter a key to exit")
        input()
        return
    # Step 3: Send configuration commands
    # Example configuration commands
    config_commands1 = [
        "enable",
        "configure terminal",
            "no ip cef",
            "service internal",
            "hostname etel",
            "ip domain-name cloudetel.com",        
    ]
    send_commands(ser, config_commands1)
    config_commands_rsa = [        
        
        "crypto key generate rsa",            
    ]
    send_commands_rsa(ser, config_commands_rsa)
    config_commands2 = [        
        
        "end",           
    ]
    send_commands(ser, config_commands2)
    config_commands = [
        "enable",
        "configure terminal",            
            "interface FastEthernet4",
                f"ip address {json_response['interface_wan_ip']} {json_response['interface_wan_netmask']}",
                "no shut",
                "duplex auto",
                "speed auto",
                "end",

        "configure terminal",
            f"ip route {json_response['dialerserverip']} 255.255.255.255 {json_response['interface_wan_gateway']}",
            "end",

        "configure terminal",
            "vpdn enable",
            "vpdn-group reachlink",
                "request-dialin",
                "protocol pptp",
                "pool-member 1",
                f"initiate-to ip {json_response['dialerserverip']}",
                "end",

        "configure terminal",
            "interface Dialer1",
                f"ip address {json_response['dialer_client_ip']} {json_response['dialer_netmask']}",
                "ip mtu 1412",
                "encapsulation ppp",
                "ip tcp adjust-mss 1312",
                "dialer pool 1",
                "dialer idle-timeout 0",
                "dialer string 1",
                "dialer persistent",
                "dialer vpdn",
                "dialer-group 1",
                "ppp authentication chap callin",
                f"ppp chap hostname {json_response['dialer_username']}",
                f"ppp chap password {json_response['dialer_password']}",                
                "end",   

        "configure terminal",
            f"access-list 170 permit ip {json_response['hub_dialer_network']} {json_response['hub_dialer_wildcardmask']} any",
            "end",

        "configure terminal",
            "line vty 0 4",
                "transport in ssh",
                "access-class 170 in",
                "login local",
                "end",

        "configure terminal",
            f"username {json_response['router_username']} privilege 15 password {json_response['router_password']}",
        "end",

        "configure terminal",
            f"snmp-server community {json_response['snmpcommunitystring']} RO",
            f"snmp-server host {json_response['ubuntu_dialerclient_ip']} version 2c {json_response['snmpcommunitystring']}",
            "snmp-server enable traps snmp authentication linkdown linkup",
            'snmp-server contact "reachlink@cloudetel.com"',
            "end",
        
        "configure terminal",
            "ip route 0.0.0.0 0.0.0.0 Dialer1",
            "ip name-server 8.8.8.8",
            "end",

        "write memory",
    ]
    send_commands(ser, config_commands)

    # Close the connection
    ser.close()
    print("Configuration completed and connection closed.")
    print("Enter a key to exit")
    input()

if __name__ == "__main__":
    main()

