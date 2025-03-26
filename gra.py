import requests

# Zabbix server details
ZABBIX_WEB_URL = "https://reachlinktest.cloudetel.com/zabbix/index.php"
USERNAME = "Admin"
PASSWORD = "zabbix"
GRAPH_URL = "https://reachlinktest.cloudetel.com/zabbix/chart2.php"
# Start a session to maintain cookies
session = requests.Session()

# Step 1: Login using web form
login_payload = {
    "name": USERNAME,
    "password": PASSWORD,
    "enter": "Sign in"
}

login_response = session.post(ZABBIX_WEB_URL, data=login_payload)

# Check if login was successful
if "zbx_session" not in session.cookies.get_dict():
    print("Login failed! Check credentials.")
    exit()

print("Login successful! Proceeding to download graph...")

# Step 2: Fetch the graph image
params = {
    "graphid": 4222,  # Replace with your graph ID
    "from": "2025-03-15 00:00:00",  # Start time (Unix timestamp)
    "to": "2025-03-18 00:00:00",  # End time (Unix timestamp)
    "width": 800,
    "height": 400,
    "profileIdx": "web.graphs"
}

graph_response = session.get(GRAPH_URL, params=params)

# Step 3: Save the graph if response is an image
if "image/png" in graph_response.headers.get("Content-Type", ""):
    with open("graph.png", "wb") as f:
        f.write(graph_response.content)
    print("Graph image downloaded successfully as graph.png")
else:
    print("Failed to retrieve graph. Response:", graph_response.text)
