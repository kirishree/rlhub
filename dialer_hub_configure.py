import serial
import time
from serial.tools import list_ports

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
        time.sleep(2)  # Give the router time to process the command
        
        # Read output after sending the command
        output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
        print(f"Router output: {output}")

        # Handle interactive prompts for RSA key generation
        if "Do you really want to replace them?" in output:
            print("Sending 'yes' to replace the keys...")
            ser.write("yes\n".encode('utf-8'))
            time.sleep(2)  # Wait for router to process the response
            output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
            print(f"Router output after 'yes': {output}")

        if "How many bits in the modulus" in output:
            print("Sending '2048' for RSA key size...")
            ser.write("2048\n".encode('utf-8'))
            time.sleep(2)  # Wait for router to process the response
            output = ser.read(ser.in_waiting).decode('utf-8', errors='ignore')
            print(f"Router output after key size: {output}")

        # Check for RSA key generation confirmation
        if "Generating RSA keys" in output:
            print("RSA key generation in progress...")
def main():
    # Step 1: Identify the COM port
    target_description = "USB-to-Serial"
    com_port = find_com_port(target_description)
    if not com_port:
        print("No Cisco router found. Please check the connection.")
        return

    # Step 2: Connect to the router
    ser = connect_to_router(com_port)
    if not ser:
        return

    # Step 3: Send configuration commands
    # Example configuration commands
    
    config_commands1 = [
        "enable",
        "configure terminal",
            "no ip cef",
            "service internal",
            "hostname etelhub",
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
        
        "configure terminal",
            "interface FastEthernet4",
                "ip address {interface_wan_ip} {interface_wan_netmask}",
                "duplex auto",
                "speed auto",
                "end",
        
        "configure terminal",
            "ip route 0.0.0.0 0.0.0.0 {interface_wan_gateway}",
            "ip name-server 8.8.8.8",
            "end",

        "configure terminal",
            "ip dhcp pool reachlink",
                "network {dialernetwork} {dialernetmask}",
                "default-router {dialerhubip}",
                "end",
                
        "configure terminal",
            "vpdn enable",
            "vpdn-group reachlink",
                "accept-dialin",
                "protocol any",
                "virtual-template 1",
                "source-ip {hubip}",
                "no l2tp tunnel authentication",
                "end",

        "configure terminal",
            "interface loopback1",
                "ip address {dialerhubip} {dialernetmask}",
                "end",

        "configure terminal",
            "interface virtual-template1",
                "ip unnumbered loopback1",
                "ip nat inside",
                "ip virtual-reassembly in",
                "peer default ip address dhcp-pool reachlink",
                "no keepalive",
                "ppp authentication pap callin",
                "end",

        "configure terminal",
            "access-list 170 permit ip {ubuntuhubip} 0.0.0.0 any",
            "end",   

        "configure terminal",
            "line vty 0 4",
                "transport in ssh",
                "access-class 170 in",
                "login local",
                "end",

        "configure terminal",
            "username {router_username} privilege 15 password {router_password}",
            "username etelhub password etel@123.com",
            "end",

        "configure terminal",
            "snmp-server community {snmpcommunitystring} RO",
            "snmp-server host {ubuntuhubip} version 2c {snmpcommunitystring}",
            "snmp-server enable traps snmp authentication linkdown linkup",
            'snmp-server contact "reachlink@cloudetel.com"',
            "end",

        "write memory",
    ]
    send_commands(ser, config_commands)

    # Close the connection
    ser.close()
    print("Configuration completed and connection closed.")

if __name__ == "__main__":
    main()

