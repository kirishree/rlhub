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
    #reg_devices = coll_registered_organization.find({},{"_id":0, "subscription_from":0, "subscription_to":0})
    for reg_device in coll_registered_organization.find({},{"_id":0, "subscription_from":0, "subscription_to":0}):
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
        
        with open("/root/reachlink/reg_devices.json", "w") as f:
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
            org_info["total_no_active spokes"] = 0
            org_info["total_no_inactive spokes"] = 0
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
                    inactive_spokes = []         
                    for midevice in device["microtek_spokes_info"]:
                        spoke_ip = midevice["tunnel_ip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            midevice["status"] = "active"
                            no_midevice_active += 1
                            active_spokes.append(midevice["branch_location"])
                            midevice["status"] = "inactive"
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
                    for cidevice in device["cisco_spokes_info"]:
                        spoke_ip = cidevice["dialerip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            cidevice["status"] = "active"
                            active_spokes.append(cidevice["branch_location"])
                            no_cidevice_active += 1
                        else:
                            cidevice["status"] = "inactive"
                            inactive_spokes.append(cidevice["branch_location"])
                            no_cidevice_inactive += 1
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
                    for rodevice in device["robustel_spokes_info"]:
                        spoke_ip = rodevice["tunnel_ip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            rodevice["status"] = "active"
                            active_spokes.append(rodevice["branch_location"])
                            no_rodevice_active += 1
                        else:
                            rodevice["status"] = "inactive"
                            inactive_spokes.append(rodevice["branch_location"])
                            no_rodevice_inactive += 1
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
                    for ubdevice in device["ubuntu_spokes_info"]:
                        spoke_ip = ubdevice["tunnel_ip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            ubdevice["status"] = "active"
                            active_spokes.append(ubdevice["branch_location"])
                            no_ubdevice_active += 1
                        else:
                            ubdevice["status"] = "inactive"
                            inactive_spokes.append(ubdevice["branch_location"])
                            no_ubdevice_inactive += 1
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
                                         "inactive_spokes": inactive_spokes,
                                         "spokes_info":{"microtek_spokes": {"spokes_info": microtek_info,
                                                             "no_active_spokes": no_midevice_inactive,
                                                             "no_inactive_spokes": no_midevice_inactive},
                                                        "cisco_spokes": {"spokes_info": cisco_info,
                                                             "no_active_spokes": no_cidevice_inactive,
                                                             "no_inactive_spokes": no_cidevice_inactive},
                                                        "robustel_spokes": {"spokes_info": robustel_info,
                                                             "no_active_spokes": no_rodevice_inactive,
                                                             "no_inactive_spokes": no_rodevice_inactive},
                                                        "ubuntu_spokes":{"spokes_info": ubuntu_info,
                                                             "no_active_spokes": no_ubdevice_inactive,
                                                             "no_inactive_spokes": no_ubdevice_inactive}
                                                        }
                                        }
                    org_info["hub_info"].append(reachlinkhub_info)
                    org_info["total_no_active spokes"] += no_active_spoke
                    org_info["total_no_inactive_spokes"] += no_inactive_spoke
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
                    ciscospokes_info = []
                    for ciscospoke in device["cisco_spokes_info"]:
                        spoke_ip = ciscospoke["dialerip"].split("/")[0]
                        connectedStatus = check_tunnel_connection(spoke_ip)
                        if connectedStatus: 
                            ciscospoke["status"] = "active"
                            active_ciscospokes.append(ciscospoke["branch_location"])
                            no_active_ciscospokes += 1
                        else:
                            ciscospoke["status"] = "inactive"
                            inactive_ciscospokes.append(ciscospoke["branch_location"])
                            no_inactive_ciscospokes += 1
                        ciscospokes_info.append({  "uuid": ciscospoke["uuid"],
                                                    "tunnel_ip": ciscospoke["dialerip"],
                                                    "public_ip":ciscospoke["dialer_hub_ip"],
                                                    "branch_location": ciscospoke.get("branch_location", ""),
                                                    "subnet": ciscospoke.get("subnet", []),
                                                    "vrf": ciscospoke.get("vrf", ""),                                                
                                                    "hub_ip":ciscospoke.get("hub_ip", ""),
                                                    "host_id": ciscospoke.get("host_id", ""),
                                                    "status": ciscospoke.get("status", ""),
                                                    "spokedevice_name": ciscospoke.get("spokedevice_name", "")
                                                  })
                    ciscohub_info = {"hub_ip": device["cisco_hub_info"]["hub_ip"].split("/")[0],
                                     "hub_location":device["cisco_hub_info"]["branch_location"],
                                         "hub_status":hubstatus,
                                         "hub_uuid": device["cisco_hub_info"]["uuid"],
                                         "hub_host_id": device["cisco_hub_info"]["host_id"],
                                         "no_active_spoke":no_active_ciscospokes,
                                         "no_inactive_spoke":no_inactive_ciscospokes,
                                         "active_spokes": active_ciscospokes,
                                         "inactive_spokes": inactive_ciscospokes,
                                         "spokes_info": ciscospokes_info
                                    }
                    org_info["hub_info"].append(ciscohub_info)
                    org_info["total_no_active spokes"] += no_active_ciscospokes
                    org_info["total_no_inactive_spokes"] += no_inactive_ciscospokes 
            final_data.append(org_info)                    
        print(final_data)
        print("sleep")
        time.sleep(10)    
if __name__ == "__main__":
    main()
