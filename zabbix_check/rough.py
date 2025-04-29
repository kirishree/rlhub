import ipaddress
import requests
import subprocess
import os
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

try:
    command = f"sudo iptables -D INPUT -s 10.8.0.3 -j DROP"
    subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
    os.system("sudo netfilter-persistent save")
except Exception as e:
    print(e)
