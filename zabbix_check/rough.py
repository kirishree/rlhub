import ipaddress
import requests
import subprocess
import os
from datetime import datetime
from dateutil.relativedelta import relativedelta
url = "https://dev-api.cloudetel.com/api/v1/"
addr = "192.168.23.149/30"
corrected_subnet = ipaddress.ip_network(addr, strict=False)
#print(corrected_subnet)
#print(round(3600/60))

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
print("corrrr",corrected_dst)              
dst_netmask = str(ipaddress.IPv4Network(corrected_dst.netmask))
print("dst", dst_netmask)
destination = "10.8.0.22"
corrected_subnet = ipaddress.ip_network("10.8.0.0/24", strict=False)
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
                if current_datetime < to_date:
                    return 'True', user_role, org_id, user_id, first_name, last_name
            else:
                    return 'Not Subscribed for ReachLink', False
        else:
                return 'Not Subscribed for any services', False
    except:
        return 'Internal Server Error', False
check_onboarding("cejavak731@wermink.com", "cejavak731@wermink.com")