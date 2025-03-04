import subprocess
import time
import json
import smtplib
import os
import pymongo
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import ipaddress
import os
import subprocess
import requests
from decouple import config
hub_ip = "185.69.209.251"
mongo_uri = config('DB_CONNECTION_STRING')
client = pymongo.MongoClient(mongo_uri)
db_tunnel = client["reach_link"]
coll_spoke_disconnect = db_tunnel["spoke_disconnect"]
coll_registered_organization = db_tunnel["registered_organization"]
tunnel_states = {}
last_disconnected_time = {}

resource_notify_active = True
resource_notify_inactive = True

smtp_server = "p3plzcpnl506439.prod.phx3.secureserver.net"  # Your SMTP server address
smtp_port = 587  # SMTP server port (587 for TLS, 465 for SSL)
sender_email = 'reachlink@cloudetel.com'  # Your email address
sender_password = 'Etel@123!@#'  # Your email password
subject = 'Alert ReachLink Spoke InActive '

# Zabbix API URL
zabbix_api_url = 'http://185.69.209.251/zabbix/api_jsonrpc.php'  # Replace with your Zabbix API URL

# Zabbix API credentials
username = 'Admin'
password = 'zabbix'

# Api key
auth_token = "de4bc85eca6a76481473f6e4efa71812ee7995c02ace600a62b750bc04841810"

# Create a session
session = requests.Session()
reachlink_current_info = []

def get_history(itemid):    
    get_history = {
        "jsonrpc": "2.0",
        "method": "history.get",
        "params": {
            "output": "extend",
            "itemids": itemid,
            "sortfield": "clock",
            "sortorder": "DESC",
            "limit": 1 
        },
        'auth': auth_token,
        'id': 1,
    }
    try:
        history_response = session.post(zabbix_api_url, json=get_history)
        history_result1 = history_response.json()
        history_result = history_result1.get('result')
        print(history_result1)
        if 'error' in history_result:
            print(f"Failed to get item list: {history_result['error']['data']}")
            return False
        else:
            return history_result[0]["value"]                       
    except Exception as e:
        print(f"Failed to get Host list: {e}")
        return False   
    
def post_mail(subject, body_mail):    
    receiver_email = "bavya@cloudetel.com"  # Recipient's email address
    subject = subject
    body = f'{body_mail}.'
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))
    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()  # Use TLS encryption
        server.login(sender_email, sender_password)
        text = message.as_string()
        server.sendmail(sender_email, receiver_email, text)        
        print("Email sent successfully!")
        server.quit()  # Close the connection to the server
    except Exception as e:       
        print(f"An error occurred while sending Email: {str(e)}")
    
        
    
#Function to test the tunnel is connected active
def check_tunnel_connection(Remote_tunnel_ip):
    try:        
        command = (f"ping -c 3  {Remote_tunnel_ip}")
        output = subprocess.check_output(command.split()).decode()        
        return True         
      
    except subprocess.CalledProcessError:
        return False
		
def main():
    data = []
    for reg_device in coll_registered_organization.find({}, {"_id":0}):
        reg_device['subscription_from'] = str(reg_device['subscription_from'])
        reg_device['subscription_to'] = str(reg_device['subscription_to'])
        if "_id" in reg_device:
            reg_device['_id'] = str(reg_device['_id'])
        data.append(reg_device)
    with open("/root/reachlink/reg_devices.json", "w") as f:
       json.dump(data, f)
       f.close()
    while(1):
        global resource_notify_active
        global resource_notify_inactive
        total_branches = []
        active_branches = []
        inactive_branches = []
        
        with open("/root/reachlink/reg_devices.json", "r") as f:
            registered_organization = json.load(f)
            f.close()
        final_data = []
        for org in registered_organization:
            org_info = {}
            org_info['organization_id'] = org["organization_id"]
            org_info["hub_info"] = []
            org_info["no_of_hubs"] = 0
            org_info["no_active_hubs"] = 0
            org_info["no_inactive_hubs"] = 0
            org_info["active_hubs"] =[]
            org_info["inactive_hubs"] = []
            org_info["total_no_active_spokes"] = 0
            org_info["total_no_inactive_spokes"] = 0
            org_info["hub_info_only"] = []
            org_info["branch_info_only"] = []
            for device in org["registered_devices"]:
                if "reachlink_hub_info" in device:
                    org_info["no_of_hubs"] += 1 
                    org_info["no_active_hubs"] += 1
                    microtek_info = []
                    robustel_info = []
                    cisco_info = []
                    ubuntu_info = []  
                    no_midevice_active = 0
                    no_midevice_inactive = 0   
                    no_rodevice_active = 0
                    no_rodevice_inactive = 0 
                    no_cidevice_active = 0
                    no_cidevice_inactive = 0 
                    no_ubdevice_active = 0
                    no_ubdevice_inactive = 0   
                    active_spokes = []  
                    bandwidth_info = []
                    inactive_spokes = []         
                    for midevice in device["microtek_spokes_info"]:
                        spoke_ip = midevice["tunnel_ip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            midevice["status"] = "active"
                            no_midevice_active += 1
                            active_spokes.append(midevice["branch_location"]) 
                            bits_received = get_history(midevice["itemid_received"])
                            bits_sent = get_history(midevice["itemid_sent"])
                            bandwidth_info.append({"branch_location": midevice["branch_location"],
                                                   "bits_recieved": bits_received,
                                                    "bits_sent": bits_sent })
                        else:
                            midevice["status"] = "inactive"
                            bandwidth_info.append({"branch_location": midevice["branch_location"],
                                                   "bits_recieved": 0,
                                                    "bits_sent": 0 })
                            no_midevice_inactive += 1
                            inactive_spokes.append(midevice["branch_location"])
                        microtek_info.append({  "uuid": midevice["uuid"],
                                                    "tunnel_ip": midevice["tunnel_ip"],
                                                    "public_ip":midevice["public_ip"],
                                                    "branch_location": midevice.get("branch_location", ""),
                                                    "subnet": midevice.get("subnet", []),
                                                    "vrf": midevice.get("vrf", ""),                                                
                                                    "hub_ip":midevice.get("hub_ip", ""),
                                                    "host_id": midevice.get("host_id", ""),
                                                    "status": midevice.get("status", ""),
                                                    "spokedevice_name": midevice.get("spokedevice_name", "")
                                                  })
                        org_info["branch_info_only"].append({  "uuid": midevice["uuid"],
                                                    "tunnel_ip": midevice["tunnel_ip"],
                                                    "public_ip":midevice["public_ip"],
                                                    "branch_location": midevice.get("branch_location", ""),
                                                    "subnet": midevice.get("subnet", []),
                                                    "vrf": midevice.get("vrf", ""),                                                
                                                    "hub_ip":midevice.get("hub_ip", ""),
                                                    "host_id": midevice.get("host_id", ""),
                                                    "status": midevice.get("status", ""),
                                                    "spokedevice_name": midevice.get("spokedevice_name", "")
                                                  })
                    for cidevice in device["cisco_spokes_info"]:
                        spoke_ip = cidevice["dialerip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            cidevice["status"] = "active"
                            active_spokes.append(cidevice["branch_location"])
                            no_cidevice_active += 1
                            bits_received = get_history(cidevice["itemid_received"])
                            bits_sent = get_history(cidevice["itemid_sent"])
                            bandwidth_info.append({"branch_location": cidevice["branch_location"],
                                                   "bits_recieved": bits_received,
                                                    "bits_sent": bits_sent })
                        else:
                            cidevice["status"] = "inactive"
                            inactive_spokes.append(cidevice["branch_location"])
                            no_cidevice_inactive += 1                            
                            bandwidth_info.append({"branch_location": cidevice["branch_location"],
                                                   "bits_recieved": 0,
                                                    "bits_sent": 0 })
                        cisco_info.append({  "uuid": cidevice["uuid"],
                                                    "tunnel_ip": cidevice["dialerip"],
                                                    "public_ip":cidevice["dialer_hub_ip"],
                                                    "branch_location": cidevice.get("branch_location", ""),
                                                    "subnet": cidevice.get("subnet", []),
                                                    "vrf": cidevice.get("vrf", ""),                                                
                                                    "hub_ip":cidevice.get("hub_ip", ""),
                                                    "host_id": cidevice.get("host_id", ""),
                                                    "status": cidevice.get("status", ""),
                                                    "spokedevice_name": cidevice.get("spokedevice_name", "")
                                                  })
                        org_info["branch_info_only"].append({  "uuid": cidevice["uuid"],
                                                    "tunnel_ip": cidevice["dialerip"],
                                                    "public_ip":cidevice["dialer_hub_ip"],
                                                    "branch_location": cidevice.get("branch_location", ""),
                                                    "subnet": cidevice.get("subnet", []),
                                                    "vrf": cidevice.get("vrf", ""),                                                
                                                    "hub_ip":cidevice.get("hub_ip", ""),
                                                    "host_id": cidevice.get("host_id", ""),
                                                    "status": cidevice.get("status", ""),
                                                    "spokedevice_name": cidevice.get("spokedevice_name", "")
                                                  })
                    for rodevice in device["robustel_spokes_info"]:
                        spoke_ip = rodevice["tunnel_ip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            rodevice["status"] = "active"
                            active_spokes.append(rodevice["branch_location"])
                            no_rodevice_active += 1
                            bits_received = get_history(rodevice["itemid_received"])
                            bits_sent = get_history(rodevice["itemid_sent"])
                            bandwidth_info.append({"branch_location": rodevice["branch_location"],
                                                   "bits_recieved": bits_received,
                                                    "bits_sent": bits_sent })
                        else:
                            rodevice["status"] = "inactive"
                            inactive_spokes.append(rodevice["branch_location"])
                            no_rodevice_inactive += 1
                           
                            bandwidth_info.append({"branch_location": rodevice["branch_location"],
                                                   "bits_recieved": 0,
                                                    "bits_sent": 0})
                        robustel_info.append({  "uuid": rodevice["uuid"],
                                                    "tunnel_ip": rodevice["tunnel_ip"],
                                                    "public_ip":rodevice.get("public_ip", "None"),
                                                    "branch_location": rodevice.get("branch_location", ""),
                                                    "subnet": rodevice.get("subnet", []),
                                                    "vrf": rodevice.get("vrf", ""),                                                
                                                    "hub_ip":rodevice.get("hub_ip", ""),
                                                    "host_id": rodevice.get("host_id", ""),
                                                    "status": rodevice.get("status", ""),
                                                    "spokedevice_name": rodevice.get("spokedevice_name", "")
                                                  })
                        org_info["branch_info_only"].append({  "uuid": rodevice["uuid"],
                                                    "tunnel_ip": rodevice["tunnel_ip"],
                                                    "public_ip":rodevice.get("public_ip", "None"),
                                                    "branch_location": rodevice.get("branch_location", ""),
                                                    "subnet": rodevice.get("subnet", []),
                                                    "vrf": rodevice.get("vrf", ""),                                                
                                                    "hub_ip":rodevice.get("hub_ip", ""),
                                                    "host_id": rodevice.get("host_id", ""),
                                                    "status": rodevice.get("status", ""),
                                                    "spokedevice_name": rodevice.get("spokedevice_name", "")
                                                  })
                    for ubdevice in device["ubuntu_spokes_info"]:
                        spoke_ip = ubdevice["tunnel_ip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            ubdevice["status"] = "active"
                            active_spokes.append(ubdevice["branch_location"])
                            no_ubdevice_active += 1
                            bits_received = get_history(ubdevice["itemid_received"])
                            bits_sent = get_history(ubdevice["itemid_sent"])
                            bandwidth_info.append({"branch_location": ubdevice["branch_location"],
                                                   "bits_recieved": bits_received,
                                                    "bits_sent": bits_sent })
                        else:
                            ubdevice["status"] = "inactive"
                            inactive_spokes.append(ubdevice["branch_location"])
                            no_ubdevice_inactive += 1                            
                            bandwidth_info.append({"branch_location": midevice["branch_location"],
                                                   "bits_recieved": 0,
                                                    "bits_sent": 0 })
                        ubuntu_info.append({  "uuid": ubdevice["uuid"],
                                                    "tunnel_ip": ubdevice["tunnel-ip"],
                                                    "public_ip":ubdevice.get("public_ip", "None"),
                                                    "branch_location": ubdevice.get("branch_location", ""),
                                                    "subnet": ubdevice.get("subnet", []),
                                                    "vrf": ubdevice.get("vrf", ""),                                                
                                                    "hub_ip":ubdevice.get("hub_ip", ""),
                                                    "host_id": ubdevice.get("host_id", ""),
                                                    "status": ubdevice.get("status", ""),
                                                    "spokedevice_name": ubdevice.get("spokedevice_name", "")
                                                  })
                        org_info["branch_info_only"].append({  "uuid": ubdevice["uuid"],
                                                    "tunnel_ip": ubdevice["tunnel-ip"],
                                                    "public_ip":ubdevice.get("public_ip", "None"),
                                                    "branch_location": ubdevice.get("branch_location", ""),
                                                    "subnet": ubdevice.get("subnet", []),
                                                    "vrf": ubdevice.get("vrf", ""),                                                
                                                    "hub_ip":ubdevice.get("hub_ip", ""),
                                                    "host_id": ubdevice.get("host_id", ""),
                                                    "status": ubdevice.get("status", ""),
                                                    "spokedevice_name": ubdevice.get("spokedevice_name", "")
                                                  })
                    no_active_spoke = no_cidevice_active + no_midevice_active +no_rodevice_active + no_ubdevice_active
                    no_inactive_spoke = no_cidevice_inactive + no_midevice_inactive + no_rodevice_inactive + no_ubdevice_inactive
                    reachlinkhub_info = {"hub_location": "Reachlink_server",
                                         "hub_ip":hub_ip,
                                         "hub_status":"active",
                                         "hub_uuid": device["reachlink_hub_info"]["uuid"],
                                         "hub_host_id": device["reachlink_hub_info"]["host_id"],
                                         "no_active_spoke":no_active_spoke,
                                         "no_inactive_spoke":no_inactive_spoke,
                                         "active_spokes": active_spokes,
                                         "bandwidth_info": bandwidth_info,
                                         "inactive_spokes": inactive_spokes,
                                         "spokes_info":{"microtek_spokes": {"spokes_info": microtek_info,
                                                             "no_active_spokes": no_midevice_active,
                                                             "no_inactive_spokes": no_midevice_inactive},
                                                        "cisco_spokes": {"spokes_info": cisco_info,
                                                             "no_active_spokes": no_cidevice_active,
                                                             "no_inactive_spokes": no_cidevice_inactive},
                                                        "robustel_spokes": {"spokes_info": robustel_info,
                                                             "no_active_spokes": no_rodevice_active,
                                                             "no_inactive_spokes": no_rodevice_inactive},
                                                        "ubuntu_spokes":{"spokes_info": ubuntu_info,
                                                             "no_active_spokes": no_ubdevice_active,
                                                             "no_inactive_spokes": no_ubdevice_inactive}
                                                        }
                                        }
                    org_info["hub_info"].append(reachlinkhub_info)
                    org_info["total_no_active_spokes"] += no_active_spoke
                    org_info["total_no_inactive_spokes"] += no_inactive_spoke
                    org_info["hub_info_only"].append({"branch_location": "Reachlink_server",
                                         "hub_ip":hub_ip,
                                         "hub_status":"active",
                                         "uuid": device["reachlink_hub_info"]["uuid"],
                                         "host_id": device["reachlink_hub_info"]["host_id"],
                                         "hub_dialer_ip_cidr": "10.8.0.1"})               

                if "cisco_hub_info" in device:
                    org_info["no_of_hubs"] += 1 
                    spoke_ip = device["cisco_hub_info"]["hub_ip"].split("/")[0]
                    connectedStatus = check_tunnel_connection(spoke_ip)
                    if connectedStatus: 
                        device["status"] = "active"
                        hubstatus = "active"
                        org_info["active_hubs"].append(device["cisco_hub_info"]["branch_location"])
                        org_info["no_active_hubs"] += 1
                    else:
                        device["status"] = "inactive"
                        hubstatus ="inactive"
                        org_info["inactive_hubs"].append(device["cisco_hub_info"]["branch_location"])
                        org_info["no_inactive_hubs"] += 1
                    no_active_ciscospokes = 0
                    no_inactive_ciscospokes =0
                    active_ciscospokes = []
                    inactive_ciscospokes = []
                    bandwidth_info_cisco = []
                    ciscospokes_info = []
                    for ciscospoke in device["cisco_spokes_info"]:
                        spoke_ip = ciscospoke["dialerip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            ciscospoke["status"] = "active"
                            active_ciscospokes.append(ciscospoke["branch_location"])
                            no_active_ciscospokes += 1
                            bits_received = get_history(ciscospoke["branch_location"]["itemid_received"])
                            bits_sent = get_history(ciscospoke["branch_location"]["itemid_sent"])
                            bandwidth_info_cisco.append({"branch_location": ciscospoke["branch_location"]["branch_location"],
                                                   "bits_recieved": bits_received,
                                                    "bits_sent": bits_sent })
                        else:
                            ciscospoke["status"] = "inactive"
                            inactive_ciscospokes.append(ciscospoke["branch_location"])
                            no_inactive_ciscospokes += 1
                            bandwidth_info_cisco.append({"branch_location": ciscospoke["branch_location"],
                                                   "bits_recieved": 0,
                                                    "bits_sent": 0 })
                        ciscospokes_info.append({  "uuid": ciscospoke["uuid"],
                                                    "tunnel_ip": ciscospoke["dialerip"],
                                                    "public_ip":ciscospoke["dialer_hub_ip"],
                                                    "branch_location": ciscospoke.get("branch_location", ""),
                                                    "subnet": ciscospoke.get("subnet", []),
                                                    "vrf": ciscospoke.get("vrf", ""),                                                
                                                    "hub_ip":ciscospoke.get("dialer_hub_ip", ""),
                                                    "host_id": ciscospoke.get("host_id", ""),
                                                    "status": ciscospoke.get("status", ""),
                                                    "spokedevice_name": ciscospoke.get("spokedevice_name", "")
                                                  })
                        org_info["branch_info_only"].append({  "uuid": ciscospoke["uuid"],
                                                    "tunnel_ip": ciscospoke["dialerip"],
                                                    "public_ip":ciscospoke["dialer_hub_ip"],
                                                    "branch_location": ciscospoke.get("branch_location", ""),
                                                    "subnet": ciscospoke.get("subnet", []),
                                                    "vrf": ciscospoke.get("vrf", ""),                                                
                                                    "hub_ip":ciscospoke.get("dialer_hub_ip", ""),
                                                    "host_id": ciscospoke.get("host_id", ""),
                                                    "status": ciscospoke.get("status", ""),
                                                    "spokedevice_name": ciscospoke.get("spokedevice_name", "")
                                                  })
                    ciscohub_info = {"hub_ip": device["cisco_hub_info"]["hub_ip"].split("/")[0],
                                     "hub_location":device["cisco_hub_info"]["branch_location"],
                                         "hub_status":hubstatus,
                                         "hub_uuid": device["cisco_hub_info"]["uuid"],
                                         "hub_host_id": device.get("cisco_hub_info", {}).get("host_id", ""),
                                         "no_active_spoke":no_active_ciscospokes,
                                         "no_inactive_spoke":no_inactive_ciscospokes,
                                         "bandwidth_info":bandwidth_info_cisco,
                                         "active_spokes": active_ciscospokes,
                                         "inactive_spokes": inactive_ciscospokes,
                                         "spokes_info": ciscospokes_info
                                    }
                    org_info["hub_info"].append(ciscohub_info)
                    org_info["total_no_active_spokes"] += no_active_ciscospokes
                    org_info["total_no_inactive_spokes"] += no_inactive_ciscospokes 
                    org_info["hub_info_only"].append({"branch_location": device["cisco_hub_info"]["branch_location"],
                                         "hub_ip":device["cisco_hub_info"]["hub_ip"].split("/")[0],
                                         "hub_status":hubstatus,
                                         "uuid": device["cisco_hub_info"]["uuid"],
                                         "host_id": device.get("cisco_hub_info", {}).get("host_id", ""),
                                         "hub_dialer_ip_cidr": device["cisco_hub_info"]["hub_dialer_ip_cidr"]
                                         })   
            final_data.append(org_info) 
        with open("/root/reachlink/device_info.json", "w") as f:
            json.dump(final_data, f)
            f.close()                   
        print("sleep")
        time.sleep(10)    
if __name__ == "__main__":
    main()
