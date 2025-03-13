import time
import json
import requests
import getpass
import re
import ipaddress
import paramiko

# Function to send a command and wait for the router's prompt
def send_command(shell, command, wait_time=2):
    shell.send(command + '\n')
    time.sleep(wait_time)  # Wait for the command to be processed  
    return 

def send_command_wo(shell, command, delay=1):
    shell.send(command + '\n')
    time.sleep(delay)
    output = shell.recv(65535).decode('utf-8')
    return output


def is_valid_ip(ip):
    """Check if the IP address is valid (IPv4 or IPv6)."""
    try:
        ipaddress.ip_address(ip)  # If this doesn't raise an error, it's a valid IP
        return True
    except ValueError:
        return False
    
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
    while True:
        hubip = input("Enter the HUB IP: ")
        if is_valid_ip(hubip):
            break
        else:
            print("❌ Invalid IP format. Please enter a valid IP.")
    bl = branch_location.lower()
    uuid = bl + "_" + hubip + "_ciscodevice.net"
    urllogin = "http://185.69.209.251:5000/auth"
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
        print("Error while getting configuration: {e}")
        print("Enter a key to exit...")
        input()
        return
    url = "http://185.69.209.251:5000/get_ciscospoke_config"
    # Set the headers to indicate that you are sending JSON data
    headers = {"Content-Type": "application/json",
               "Authorization": f"Bearer {access_token}"}
    userinfo = {"username": username,
                "password": password,
                "uuid": uuid} 
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
        print("Error while getting configuration: {e}")
        print("Enter a key to exit...")
        input()
        return
    # Define the router details
    router_ip = "78.110.5.94"
    username = "admin"
    password = "123@aabid.com"
    # Create an SSH client
    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
    # Connect to the router
        ssh_client.connect(hostname=router_ip, username=username, password=password, timeout=30, banner_timeout=60)
    except Exception as e:
        print(f"SSH Connection Error: {e}")
        print("Configuration completed and connection closed.")
        print("Enter a key to exit")
        input()
        return False

    # Open an interactive shell session
    shell = ssh_client.invoke_shell()

    # Add a delay to allow the shell to be ready
    time.sleep(1)
    # Enter enable mode
    output = send_command_wo(shell, 'enable')
    if "Password" in output:  # Prompt for enable password
        send_command_wo(shell, password)
        
    # Step 3: Send configuration commands
    # Example configuration commands
    config_commands1 = [       
        "configure terminal",
            "no ip cef",
            "service internal",
            "hostname etel",
            "ip domain-name cloudetel.com",        
    ]
    for command in config_commands1:
        send_command(shell, command)
    
    send_command_wo(shell, "crypto key generate rsa" )
    time.sleep(3)
    send_command_wo(shell, "yes" )
    time.sleep(3)
    output = send_command_wo(shell, "2048" )
    time.sleep(3)
    # Check for RSA key generation confirmation
    if "Generating RSA keys" in output:
            print("RSA key generation in progress...")
    send_command(shell, "end")
    config_commands = [
        "configure terminal",            
            "interface FastEthernet4",
                f"ip address {json_response['interface_wan_ip']} {json_response['interface_wan_netmask']}",
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
    for command in config_commands:
        send_command(shell, command)
    # Close the connection
    ssh_client.close()
    print("Configuration completed and connection closed.")
    print("Enter a key to exit")
    input()
    return True

if __name__ == "__main__":
    main()

