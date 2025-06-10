import ipaddress
import requests
import subprocess
import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
url = "https://dev-api.cloudetel.com/api/v1/"
addr = "192.168.23.149/30"
corrected_subnet = ipaddress.ip_network(addr, strict=False)
import random



private_ranges = [
        (ipaddress.IPv4Network("10.0.0.0/8"), random.randint(8,32)),
        (ipaddress.IPv4Network("172.16.0.0/12"), random.randint(16,32)),
        (ipaddress.IPv4Network("192.168.0.0/16"), random.randint(24,32)),
    ]
addroute = []
for i in range(0,20):
        network_base, base_prefix = random.choice(private_ranges)
        #prefix = random.randint(0,32)
        # Calculate how many networks of desired prefix fit in this base range
        #max_subnets = 2 ** (prefix - base_prefix)
        #subnet_index = random.randint(0, max_subnets - 1)        
        # Get the nth subnet of the desired prefix
        subnets = list(network_base.subnets(new_prefix=base_prefix))
        subnet_index = random.randint(0, len(subnets)-1)
        addroute.append({"destination": str(subnets[subnet_index]),
                         "gateway": "10.8.0.19"})
print("addrouet.................",addroute)
#print(corrected_subnet)
#print(round(3600/60))
ss = ipaddress.ip_network("192.168.7.23/24", strict=False)
print(ss)
headers = {"Content-Type": "application/json"}

def get_organization_id(data):
    try:
        if "access_token" not in data:
            print(data)
            data_login = {
                    "email": data["username"],
                    "password": data['password']
                 }
            # Send a POST request with the data
            login_response = requests.post(url+"admin/login", json=data_login)
            if login_response.status_code == 200:
            # Parse the JSON response
                loginjson_response = login_response.json()
                access_token = loginjson_response["data"]["access_token"]
                print(loginjson_response)
            else:
                return False, data
        else:
            access_token = data["access_token"]
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        if user_response.status_code == 200:
            userjson_response = user_response.json()
            print("user me info", userjson_response)
            user_info = userjson_response["data"]["user"]
            if user_info["status"] == "ACTIVE":
                data["username"] = user_info["email"]
                return user_info["org_id"], data
            else:
                return False, data
        else:
            print(user_response)
            return False, data 
    except Exception as e:
        print(e)
        return False, data
#data = {"access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiOWI5Njc0NmE1NGEzNGY1ODhkNmNlYzAzMDMxNDA3NTEiLCJjbGFpbXMiOlsibG9naW4iLCJhZG1pbiJdLCJ0b2tlbl9pZCI6IjE2ZDk2ZjVjLTViNWEtNDI1My05N2I0LTUxMjA2N2VlZjU1ZCIsImV4cCI6MTc0NTEyNDg3OSwiaXNzIjoiaHR0cHM6Ly9jbG91ZGV0ZWwuY29tIiwiaWF0IjoxNzQ1MDM4NDc5fQ.DRRn7cwcZkzre2Vss-kiwB7iiIqaksFdTfOJxPyy5rs"}
data = {}
#data["username"] = "cejavak731@wermink.com"
#data['password'] = "cejavak731@wermink.com"
data = {'access_token': 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhMThlMWY2NjJhNzU0ODgzODhmN2E2YWMzODQyODRhNCIsInVzZXJfaWQiOiI5NTZjNTYwY2FlYjE0Y2U4ODY0NzcxMDFkZWUwM2QxYSIsImNsYWltcyI6WyJsb2dpbiIsInVzZXIiXSwidG9rZW5faWQiOiI1ZGJkNTc2ZC03ZmFiLTRhNzYtODg3My0zODc2NzM4MGE1Y2MiLCJleHAiOjE3NDUxNDEwNTYsImlzcyI6Imh0dHBzOi8vY2xvdWRldGVsLmNvbSIsImlhdCI6MTc0NTA1NDY1Nn0.LynIDV_3q5ROVwg2FC2V_tEZgW8-lZQ1Ew5Her6MWKc'}
#get_organization_id(data)
corrected_dst = ipaddress.ip_network('10.8.0.22/24', strict=False) 
iii = " switchport trunk allowed vlan 1,2,10,20,1002-1005"
print(iii.split("1002-1005"))
iiii = "% 192.168.50.0 overlaps with Loopback12"
print(iiii.split("with")[1].split(" "))
print("corrrr",corrected_dst) 
vlanname = "vlan100"
print("valid",  vlanname.split("vlan")[1] )     


vlanname = " interface FastEthernet"
print("intname",  vlanname.strip().split("interface")[1] )  

comm = "      switchport trunk allowed vlan 1,2,100,1002-1005         111"
print(comm.strip())
print("commm", comm.split(",100,")[0])
print("commm", comm.split(",100,")[1])
commmm = comm.split(",100,")[0] + ","  + comm.split(",100,")[1]
print("commm", commmm)
out = ['', '123', '124', '']
if out[-1]:
    print(out[-1])
else:
    out = out[:-1]
print(out)
intfc = "vlan1001"
print("vlanid", intfc.split("vlan"))
rr = "ii with vlan\r "
print(rr.split("ii with ")[1].split(" ")[0].split("\r")[0])


def checkkk(user):
    if user == "a":
        return True, user
    else:
        return "not a", user
chstatus, user1 = checkkk("b")
if chstatus:
    print("hi", chstatus)
else:
    print("hiii", chstatus)

interface = {"vlan_id": "100,233,433,500,33", 
             "interfacename": "f0"}
vlanid = "33"
vlanlinkinfo = []

if f"{vlanid}" == interface["vlan_id"].split(",")[0]:                    
                    updated_vlan = interface["vlan_id"].split(",")
                    vlanc = ""
                    for i in range(0,len(updated_vlan)):                          
                          if i != 0:
                            vlanc += f"{updated_vlan[i]},"
                    print("updatedvlan", updated_vlan)
                    vlancommand = f"switchport trunk allowed vlan 1,{vlanc}1002-1005"
                    vlanlinkinfo.append({"intfc": interface["interfacename"],
                                         "vlancommand": vlancommand})                    
elif f",{vlanid}," in interface["vlan_id"]:
                    updated_vlan = interface["vlan_id"].split(f",{vlanid},")
                    vlancommand = f"switchport trunk allowed vlan 1,{updated_vlan[0]},{updated_vlan[1]},1002-1005"
                    vlanlinkinfo.append({"intfc": interface["interfacename"],
                                         "vlancommand": vlancommand})   
elif f"{vlanid}" == interface["vlan_id"].split(f",")[-1]:
                    updated_vlan = interface["vlan_id"].split(",")
                    vlanc = ""
                    for i in range(0,len(updated_vlan)-1):                                                  
                        vlanc += f"{updated_vlan[i]},"                                     
                    vlancommand = f"switchport trunk allowed vlan 1,{vlanc}1002-1005"
                    vlanlinkinfo.append({"intfc": interface["interfacename"],
                                         "vlancommand": vlancommand})   
print("vlancommand")
print(vlanlinkinfo)



dst_netmask = str(ipaddress.IPv4Network(corrected_dst.netmask))
print("dst", dst_netmask)
destination = "10.8.0.22"
corrected_subnet = ipaddress.ip_network("10.8.0.10/24", strict=False)
ip_obj = ipaddress.ip_address(destination)
if ip_obj in corrected_subnet:  
    response = {"message": f"Error while adding route due to address conflict {destination}"}
    print(response)      

id = []
available_numbers = [i for i in range(1,10) if i not in id]

# Pick one (e.g., the first available)
if available_numbers:
    selected = available_numbers[0]
    print("Selected:", selected)
else:
    print("No available number")


def check_onboarding(username, password):
    try:
        data_login = {
                    "email": username,
                    "password": password
                 }
        # Send a POST request with the data
        login_response = requests.post(url+"auth/login", json=data_login)
        if login_response.status_code == 200:
        # Parse the JSON response
            loginjson_response = login_response.json()
            print(loginjson_response)
            access_token = loginjson_response["data"]["access_token"]
        else:
            return 'Invalid Login & password'
        headers = {
                    "Authorization": f"Bearer {access_token}"
                  }
        user_response = requests.get(url+"users/me", headers=headers)
        if user_response.status_code == 200:
            userjson_response = user_response.json()  
            print("users info", userjson_response)          
            user_info = userjson_response["data"]["user"]
            user_role = user_info["role"]
            org_id = user_info["org_id"]
            user_id = user_info["id"]
            first_name = user_info["first_name"]
            last_name = user_info["last_name"]
        service_response = requests.get(url+"services/", headers=headers)
        if service_response.status_code == 200:
            servicejson_response = service_response.json()
            services_info = servicejson_response["data"]["services"]
            subscription_status = False
            for service in services_info:
                if service["name"] == "link":
                    subscription_status = True
            if subscription_status:
                current_datetime = datetime.now() 
                subscription_response = requests.get(url+"subscription_transactions/current", headers=headers)
                subsjson_response = subscription_response.json()
                timestamp = int(subsjson_response["data"]["created_at"])
                # Convert Unix timestamp to datetime
                from_date = datetime.utcfromtimestamp(timestamp)
                # Add Duration to get to_date
                to_date = from_date + relativedelta(months=int(subsjson_response["data"]["duration"]))
                print("2date",to_date)
                print(type(to_date))
                if current_datetime < to_date:
                    return 'True', user_role, org_id, user_id, first_name, last_name, str(to_date)
            else:
                    return 'Not Subscribed for ReachLink', False
        else:
                return 'Not Subscribed for any services', False
    except:
        return 'Internal Server Error', False
#check_onboarding("cejavak731@wermink.com", "cejavak731@wermink.com")
def test_addstaticroute_hub(client, capfd):
    # Step 1: Login to get access token
    #login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post("login_or_register", login_data, content_type="application/json")
    assert login_response.status_code == 200
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    token = login_response.json().get("access")  # Adjust this if your token key is different
    assert token is not None

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
    }
    private_ranges = [
        (ipaddress.IPv4Network("10.0.0.0/8"), random.randint(8,32)),
        (ipaddress.IPv4Network("172.16.0.0/12"), random.randint(16,32)),
        (ipaddress.IPv4Network("192.168.0.0/16"), random.randint(24,32)),
    ]
    addroute = []
    for i in range(0,20):
        network_base, base_prefix = random.choice(private_ranges)
        subnets = list(network_base.subnets(new_prefix=base_prefix))
        subnet_index = random.randint(0, len(subnets)-1)
        addroute.append({"destination": str(subnets[subnet_index]),
                         "gateway": "10.8.0.19"})
    addroute_data = {"hub_wan_ip": "185.69.209.251",
                     "uuid": "reachlinkserver.net",
                     "routes_info": addroute}
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    addstaticroute_hub_url = "addstaticroute_hub"
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Homepage Info response JSON:", response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    # Optional: Assert fields in response
    assert "Error" not in json_data[0]["message"]