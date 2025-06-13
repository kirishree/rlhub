# pytest -vs -k test_addstaticroute_hub --capture=tee-sys --html=add_route_hub.html --self-contained-html
import pytest
import random
import ipaddress
from django.urls import reverse
from django.test import override_settings
import time
import json
from pytest_html import extras
import logging
import tempfile
import os
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

@pytest.fixture
@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def auth_token(client):
    login_url = reverse("login_or_register")  # or hardcode as '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    response = client.post(login_url, login_data, content_type="application/json")
    assert response.status_code == 200
    return response.json().get("access")

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_login_response(client, capfd, extra):
    login_url = reverse("login_or_register") 
    logger.info("Login Request started")
    response = client.post(login_url, {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }, content_type="application/json")

    assert response.status_code == 200
    output = response.json()  # list or dict
    pretty_text = json.dumps(output, indent=2) 
    print("Login Response", pretty_text)
    out, err = capfd.readouterr()  
    logger.info(f"Login Response: {pretty_text}")     



@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_branch_info_view_with_token(client, capfd):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
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
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    branch_info_url = reverse("branch_info")
    response = client.get(branch_info_url, **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Branch info:", json_data)
    # Capture again
    out2, err2 = capfd.readouterr()
    # Optional: Assert fields in response
    assert "total_branches" in json_data
    assert "active_branches" in json_data
    # Optionally assert that captured output has expected text (optional)
    assert "Login response JSON:" in out
    assert "Branch info:" in out2

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.parametrize("payload,expected", [
    ({
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }, 200),
    ({"username": "admin"}, 400),
    ({}, 400),
])
@pytest.mark.django_db
def test_login(client, capfd, payload, expected):
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_response = client.post(login_url, payload, content_type="application/json")   
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    assert login_response.status_code == expected

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_login_re1(client, capfd, extra):
    login_url = reverse("login_or_register")
    response = client.post(login_url, {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }, content_type="application/json")

    assert response.status_code == 200

    output = response.json()
    pretty_text = json.dumps(output, indent=2)

    # Attach pretty-printed response to report
    extra.append(extras.text("Hii"))
    extra.append(extras.image(pretty_text, mime_type="image/png", extension="png"))

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_hub_info_view_with_token(client, capfd):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
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
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    hub_info_url = reverse("hub_info")
    response = client.get(hub_info_url, **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Hub Info response JSON:", response.json())
    # Capture output after print
    out, err = capfd.readouterr() 

    # Optional: Assert fields in response
    assert "total_hubs" in json_data
    assert "active_hubs" in json_data

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_homepage_info_view_with_token(client, capfd):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
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
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    homepage_info_url = reverse("homepage_info")
    response = client.get(homepage_info_url, **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Homepage Info response JSON:", response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    # Optional: Assert fields in response
    assert "hub_summary" in json_data
    assert "branch_summary" in json_data

def is_excluded(network):
    return (
        network.is_loopback or
        network.is_link_local or
        network.is_multicast or
        network.network_address.is_reserved or
        network.network_address.is_unspecified
    )
@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_addstaticroute_hub(client, capfd):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == 200
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    logger.info(f"Login response: {login_response.json()}")
    token = login_response.json().get("access")  # Adjust this if your token key is different
    assert token is not None

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
    }
    addroute = []
    for _ in range(20):
        while True:
            prefix_len = random.randint(8, 30)
            host_bits = 32 - prefix_len
            network_int = random.randint(0, (2**(32 - host_bits)) - 1) << host_bits
            network = ipaddress.IPv4Network((network_int, prefix_len))

            if not is_excluded(network):
                addroute.append({
                    "destination": str(network),
                    "gateway": "10.8.0.19"
                })
                break  # exit loop after valid network found
    addroute_data = {"hub_wan_ip": "185.69.209.251",
                     "uuid": "reachlinkserver.net",
                     "routes_info": addroute}
    logger.info(f"Randomly Generated routes: {addroute}")
    addstaticroute_hub_url = reverse("addstaticroute_hub")
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)
    assert response.status_code == 200
    json_data = response.json()
    print("Add Route HUB response JSON:", response.json())
    # Capture output after print
    out1, err = capfd.readouterr() 
    logger.info(f"Add Route HUB response: {response.json()}")
    # Optional: Assert fields in response
    assert "Error" not in json_data[0]["message"]
    time.sleep(10)
    getroute_data = {"hub_wan_ip": "185.69.209.251",
                     "uuid": "reachlinkserver.net"
                     }
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    getroute_hub_url = reverse("get_routing_table")
    response = client.post(getroute_hub_url, getroute_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    print("routing_table", routing_table)
     # Capture output after print
    out2, err = capfd.readouterr() 
    logger.info(f"Routing table after adding Routes: {routing_table}")
    routenotadded = []
    for addinfo in addroute:
        routeadded = False
        for routeinfo in  routing_table:
            if addinfo["destination"] == routeinfo["destination"]:
                routeadded = True
                break
        if not routeadded:
            routenotadded.append(addinfo)
    print("Not added route", routenotadded)
     # Capture output after print
    out4, err = capfd.readouterr() 
    if len(routenotadded) > 0:
        logger.info(f"Not added routes: {routenotadded}")
    assert len(routenotadded) == 0
    
@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_delstaticroute_hub(client, capfd):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == 200
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    logger.info(f"Login response: {login_response.json()}")
    token = login_response.json().get("access")  # Adjust this if your token key is different
    assert token is not None

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
    }
    getroute_data = {"hub_wan_ip": "185.69.209.251",
                     "uuid": "reachlinkserver.net"
                     }
    getroute_hub_url = reverse("get_routing_table")
    response = client.post(getroute_hub_url, getroute_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    deleteroute = []
    print("routing table before deletion", routing_table)
    # Capture output after print
    out1, err = capfd.readouterr()
    logger.info(f"Routing table before deletion: {routing_table}")
    for routeinfo in routing_table:
        if routeinfo["protocol"] == "static":
            if "0.0.0.0" not in routeinfo["destination"]:
                deleteroute.append({"destination": routeinfo["destination"],
                               "gateway": routeinfo["gateway"]})    
    delroute_data = {"hub_wan_ip": "185.69.209.251",
                     "uuid": "reachlinkserver.net",
                     "routes_info": deleteroute
                     }
    delroute_hub_url = reverse("delstaticroute_hub")
    response = client.post(delroute_hub_url, delroute_data, content_type="application/json", **headers)
    assert response.status_code == 200
    json_data = response.json()
    print("Delete Route Info response JSON:", response.json())
    # Capture output after print
    out2, err = capfd.readouterr() 
    logger.info(f"Delete route response: {json_data}")
    # Optional: Assert fields in response
    assert "Error" not in json_data[0]["message"]
    time.sleep(10)
    getroute_data = {"hub_wan_ip": "185.69.209.251",
                     "uuid": "reachlinkserver.net"
                     }
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    getroute_hub_url = reverse("get_routing_table")
    response = client.post(getroute_hub_url, getroute_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    print("routing_table after deletion", routing_table)
    # Capture output after print
    out2, err = capfd.readouterr() 
    logger.info(f"Routing table after deletion:{routing_table}")
    routenotdeleted = []
    for delinfo in deleteroute:        
        for routeinfo in  routing_table:
            if delinfo["destination"] == routeinfo["destination"]:                
                routenotdeleted.append(delinfo)
                break               
    print("Not deleted route", routenotdeleted)
    if len(routenotdeleted) > 0:
        logger.info(f"Not deleted route: {routenotdeleted}")
    assert len(routenotdeleted) == 0

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_add_route_spoke(client, capfd, extras):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == 200
    print("Login response", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    logger.info(f"Login response: {login_response.json()}")
    token = login_response.json().get("access")  # Adjust this if your token key is different
    assert token is not None

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
    }    
    addroute = []
    for _ in range(20):
        while True:
            prefix_len = random.randint(8, 30)
            host_bits = 32 - prefix_len
            network_int = random.randint(0, (2**(32 - host_bits)) - 1) << host_bits
            network = ipaddress.IPv4Network((network_int, prefix_len))
            if not is_excluded(network):
                addroute.append({
                    "subnet": str(network),
                    "gateway": "192.168.88.2"
                })
                break  # exit loop after valid network found
    addroute_data = {"tunnel_ip": "10.8.0.19",
                     "uuid": "microtek21_microtek.net",
                     "subnet_info": addroute}
    logger.info("Testing Started to add Routes in Spoke")
    logger.info(f"Randomly Generated routes: {addroute}")
    addstaticroute_hub_url = reverse("add_route_spoke")
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Add Route Spoke response JSON:", response.json())
    # Capture output after print
    out2, err = capfd.readouterr() 
    logger.info(f"Add Route Spoke response: {response.json()}")
    logger.info(f"Started to validate the added routes")
    # Optional: Assert fields in response
    assert "Error" not in json_data[0]["message"]
    time.sleep(10)
    getroute_spoke_data = {"tunnel_ip": "10.8.0.19",
                     "uuid": "microtek21_microtek.net"
                     }
    getroute_spoke_url = reverse("get_routing_table_spoke")
    response = client.post(getroute_spoke_url, getroute_spoke_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    print("Routing Table after added routes", routing_table)
    # Capture output after print
    out2, err = capfd.readouterr() 
    logger.info(f"Routing Table after added routes: {response.json()}")
    routenotadded = []
    for addinfo in addroute:
        routeadded = False
        for routeinfo in  routing_table:
            if addinfo["subnet"] == routeinfo["destination"]:
                routeadded = True
                break
        if not routeadded:
            routenotadded.append(addinfo)
    print("Not added route", routenotadded)
    if len(routenotadded) > 0:
        logger.info(f"Not added Routes: {routenotadded}")
    assert len(routenotadded) == 0
    
@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_del_staticroute_spoke(client, capfd, extra):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == 200
    login_response_data = login_response.json()  # This is now a list or dict
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    logger.info(f"Login Info Response: {login_response_data}")
    token = login_response.json().get("access")  # Adjust this if your token key is different
    assert token is not None

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
    }
    getroute_spoke_data = {"tunnel_ip": "10.8.0.19",
                     "uuid": "microtek21_microtek.net"
                     }
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    getroute_spoke_url = reverse("get_routing_table_spoke")
    response = client.post(getroute_spoke_url, getroute_spoke_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    print("Routing table of Spoke before delete", routing_table)
    # Capture again
    out2, err2 = capfd.readouterr()
    logger.info(f"Routing table of Spoke before delete: {routing_table}")
    deleteroute = []
    for routeinfo in routing_table:
        if routeinfo["protocol"] == "static":
            if "0.0.0.0/0" not in routeinfo["destination"]:
                deleteroute.append({"destination": routeinfo["destination"],
                               "gateway": routeinfo["gateway"]})    
    delroute_spoke_data = {"tunnel_ip": "10.8.0.19",
                     "uuid": "microtek21_microtek.net",
                     "routes_info": deleteroute
                     }
    delroute_spoke_url = reverse("del_staticroute_spoke")
    response = client.post(delroute_spoke_url, delroute_spoke_data, content_type="application/json", **headers)
    assert response.status_code == 200
    json_data = response.json()
    print("Delete Route response", response.json())
    # Capture output after print
    out3, err3 = capfd.readouterr() 
    logger.info(f"Delete sttsic route spoke response: {response.json()}")
    # Optional: Assert fields in response
    assert "Error" not in json_data[0]["message"]
    time.sleep(10)
    getroute_spoke_data = {"tunnel_ip": "10.8.0.19",
                     "uuid": "microtek21_microtek.net"
                     }
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    getroute_spoke_url = reverse("get_routing_table_spoke")
    response = client.post(getroute_spoke_url, getroute_spoke_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    print("Routing Table of spoke after deletion", routing_table)
     # Capture output after print
    out4, err4 = capfd.readouterr() 
    logger.info(f"Routing table of spoke after deletion: {routing_table}")
    routenotdeleted = []
    for delinfo in deleteroute:        
        for routeinfo in  routing_table:
            if delinfo["destination"] == routeinfo["destination"]:                
                routenotdeleted.append(delinfo)
                break               
    print("Not deleted routes", routenotdeleted)
     # Capture output after print
    out5, err5 = capfd.readouterr() 
    if len(routenotdeleted) > 0:
        logger.info(f"Routes not deleted: {routenotdeleted}") 
    assert len(routenotdeleted) == 0
   
@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
@pytest.mark.parametrize("payload,expected", [
    (   {   "branch_location":"pytest1",   
            "device":"robustel",
            "router_wan_ip":"192.168.88.101/24",
            "router_wan_gateway":"192.168.88.1",
            "dialer_ip":"185.69.209.251"}, 200),
    (   {   "branch_location":"pytest2",   
            "device":"microtik",
            "router_wan_ip":"192.168.88.101/24",
            "router_wan_gateway":"192.168.88.1",
            "dialer_ip":"185.69.209.251"}, 200),
    (   {   "branch_location":"pytest3",   
            "device":"cisco",
            "router_wan_ip":"192.168.88.101/24",
            "router_wan_gateway":"192.168.88.1",
            "dialer_ip":"185.69.209.251"}, 200),
    (   {   "branch_location":"pytest2"}, 400),
    ({}, 400),
])
def test_add_cisco_device(client, capfd, auth_token, payload, expected):   

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {auth_token}"
    }    
    logger.info(f"Testing add device info: {payload}")
    add_cisco_device_url = reverse("add_cisco_device")
    response = client.post(add_cisco_device_url, payload, content_type="application/json", **headers)
    assert response.status_code == expected
    if response.status_code == 200:
        assert response['Content-Type'] == 'application/zip'
        # Get the header value
        x_message = response.get("X-Message")
        assert x_message is not None

        # Parse it from JSON string to Python object (e.g., list or dict)
        parsed_message = json.loads(x_message)
        logger.info(f"Add device response: {parsed_message}")

    # Optionally check headers like `X-Message` or response.content if needed
    else:
        assert response['Content-Type'] == 'application/json'
        json_data = response.json()
        assert "message" in json_data    
        print("Add device response JSON:", response.json())
        # Capture output after print
        out1, err = capfd.readouterr() 
        logger.info(f"Add device response: {response.json()}")
    if response.status_code == 200:        
        logger.info(f"Started to validate the added device in branch info")
        branch_info_url = reverse("branch_info")
        response = client.get(branch_info_url, **headers)

        assert response.status_code == 200
        json_data = response.json()
        print("Branch info:", json_data)
        # Capture again
        out2, err2 = capfd.readouterr()
        logger.info(f"Branch info after added the device {response.json()} added  ")
        # Optional: Assert fields in response
        assert "total_branches" in json_data
        assert "active_branches" in json_data
        branch_added = False
        for branch in json_data["data"]:
            if branch["branch_location"] == payload["branch_location"]:
                branch_added = True
                logger.info(f"New Branch {payload['branch_location']} added  ")
        assert branch_added 
