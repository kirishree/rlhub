import subprocess
import time
import json
import smtplib
import os
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
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
    while(1):
        global resource_notify_active
        global resource_notify_inactive
        total_branches = []
        active_branches = []
        inactive_branches = []
        with open("/root/reachlink/total_branches.json", "r") as f:
            total_branches = json.load(f)
            f.close()
        for device in total_branches:
            spoke_ip = device["tunnel_ip"].split("/")[0]
            connectedStatus = check_tunnel_connection(spoke_ip)
            if connectedStatus: 
                device["status"] = "active"               
                active_branches.append(device)
            else:
#                post_mail(device)
                device["status"] = "inactive"
                os.system(f"ip neighbor replace {spoke_ip} lladdr {device['public_ip']} dev Reach_link1")
                inactive_branches.append(device) 
            tunnel_key = f"{spoke_ip}"
            current_state = tunnel_states.get(tunnel_key, None)

            # State change: connected -> not connected
            if current_state == "active" and device["status"] == "inactive":
                last_disconnected_time[tunnel_key] = time.time()
                subject = f"Problem: ReachLink Down at {device['branch_location']}"
                #current_time = f"{time.time() / 60:.2f}"
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                body_mail = (
                    f"Problem Started at {current_time} \n"
                    f"Problem Name: Link down at {device['branch_location']} \n"
                    "Severity: High \n"
                    f"The following routes are not Reachable: \n {device['subnet']}"
                )
                post_mail(subject, body_mail)

            # State change: not connected -> connected
            elif current_state == "inactive" and device["status"] == "active":                
                disconnected_time = last_disconnected_time.get(tunnel_key, time.time())
                downtime_seconds = time.time() - disconnected_time
                downtime_days = int(downtime_seconds // 86400)
                downtime_hours = int((downtime_seconds % 86400) // 3600)
                downtime_minutes = int((downtime_seconds % 3600) // 60)

                downtime_message = f"{downtime_days}d {downtime_hours}h {downtime_minutes}m" if downtime_days > 0 else f"{downtime_hours}h {downtime_minutes}m"

                subject = f"Resolved in {downtime_message} minutes : Tunnel Disconnected"
                body_mail = (
                    f"Problem has been resolved  at {downtime_message} \n"
                    f"Problem Name:  Link Down at between {device['branch_location']}\n"
                    f"Current Status: Active \n "
                )
                post_mail(subject, body_mail)  
             # Update the tunnel state
            tunnel_states[tunnel_key] = device["status"]          
                
        resource_notify_active = False
        with open("/root/reachlink/active_branches.json", "w") as f:
            json.dump(active_branches, f)
            f.close()
        resource_notify_active = True       
        
        resource_notify_inactive = False
        with open("/root/reachlink/inactive_branches.json", "w") as f:
            json.dump(inactive_branches, f)
            f.close()	
        with open("/root/reachlink/total_branches.json", "w") as f:
            json.dump(total_branches, f)
            f.close()
        resource_notify_inactive = True     
        #HUB status check
        with open("/root/reachlink/total_hubs.json", "r") as f:
            total_hubs = json.load(f)
            f.close()
        for device in total_hubs:
            spoke_ip = device["hub_dialer_ip"].split("/")[0]
            connectedStatus = check_tunnel_connection(spoke_ip)
            if connectedStatus: 
                device["status"] = "active"               
                active_branches.append(device)
            else:

                device["status"] = "inactive"
                 
            hub_key = f"{spoke_ip}"
            current_state = tunnel_states.get(hub_key, None)

            # State change: connected -> not connected
            if current_state == "active" and device["status"] == "inactive":
                last_disconnected_time[hub_key] = time.time()
                subject = f"Problem: ReachLink HUB Down at {device['branch_location']}"
                #current_time = f"{time.time() / 60:.2f}"
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                body_mail = (
                    f"Problem Started at {current_time} \n"
                    f"Problem Name: ReachLink HUB down at {device['branch_location']} \n"
                    "Severity: High \n"
                    
                )
                post_mail(subject, body_mail)

            # State change: not connected -> connected
            elif current_state == "inactive" and device["status"] == "active":                
                disconnected_time = last_disconnected_time.get(hub_key, time.time())
                downtime_seconds = time.time() - disconnected_time
                downtime_days = int(downtime_seconds // 86400)
                downtime_hours = int((downtime_seconds % 86400) // 3600)
                downtime_minutes = int((downtime_seconds % 3600) // 60)

                downtime_message = f"{downtime_days}d {downtime_hours}h {downtime_minutes}m" if downtime_days > 0 else f"{downtime_hours}h {downtime_minutes}m"

                subject = f"Resolved in {downtime_message} minutes : Tunnel Disconnected"
                body_mail = (
                    f"Problem has been resolved  at {downtime_message} \n"
                    f"Problem Name:  Link Down at between {device['branch_location']}\n"
                    f"Current Status: Active \n "
                )
                post_mail(subject, body_mail)  
             # Update the tunnel state
            tunnel_states[hub_key] = device["status"]         
                
        
        with open("/root/reachlink/total_hubs.json", "w") as f:
            json.dump(total_hubs, f)
            f.close()      
        time.sleep(10)    
if __name__ == "__main__":
    main()
