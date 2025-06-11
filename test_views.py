import pytest
import random
import ipaddress
from django.urls import reverse
from django.test import override_settings
import time

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
    addstaticroute_hub_url = reverse("addstaticroute_hub")
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Homepage Info response JSON:", response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
    # Optional: Assert fields in response
    assert "Error" not in json_data[0]["message"]

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
def test_addstaticroute_hub_allip(client, capfd):
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
    private_ranges = [
        (ipaddress.IPv4Network("10.0.0.0/8"), random.randint(8,32)),
        (ipaddress.IPv4Network("172.16.0.0/12"), random.randint(16,32)),
        (ipaddress.IPv4Network("192.168.0.0/16"), random.randint(24,32)),
    ]
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
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    addstaticroute_hub_url = reverse("addstaticroute_hub")
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Homepage Info response JSON:", response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
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
    out, err = capfd.readouterr() 
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
    routenotdeleted = []
    for delinfo in deleteroute:        
        for routeinfo in  routing_table:
            if delinfo["destination"] == routeinfo["destination"]:                
                routenotdeleted.append(delinfo)
                break               
    print("Not deleted route", routenotdeleted)
    assert len(routenotdeleted) == 0

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_add_route_spoke(client, capfd):
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
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    addstaticroute_hub_url = reverse("add_route_spoke")
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Homepage Info response JSON:", response.json())
    # Capture output after print
    out, err = capfd.readouterr() 
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
    print("routing_table", routing_table)
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
    assert len(routenotadded) == 0
    
@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_del_staticroute_spoke(client, capfd):
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
    getroute_spoke_data = {"tunnel_ip": "10.8.0.19",
                     "uuid": "microtek21_microtek.net"
                     }
    #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    getroute_spoke_url = reverse("get_routing_table_spoke")
    response = client.post(getroute_spoke_url, getroute_spoke_data, content_type="application/json", **headers)
    assert response.status_code == 200
    routing_table = response.json()
    print("routing table of Spoke", routing_table)
    # Capture again
    out2, err2 = capfd.readouterr()
    deleteroute = []
    for routeinfo in routing_table:
        if routeinfo["protocol"] == "static":
            if "0.0.0.0" not in routeinfo["destination"]:
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
    print("Delete Route Info response JSON:", response.json())
    # Capture output after print
    out3, err3 = capfd.readouterr() 
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
    routenotdeleted = []
    for delinfo in deleteroute:        
        for routeinfo in  routing_table:
            if delinfo["destination"] == routeinfo["destination"]:                
                routenotdeleted.append(delinfo)
                break               
    print("Not deleted route", routenotdeleted)
     # Capture output after print
    out5, err5 = capfd.readouterr() 
    assert len(routenotdeleted) == 0
    # Optionally assert that captured output has expected text (optional)
    assert "Login response JSON:" in out
    assert "routing table of Spoke" in out2
    assert "Delete Route Info response JSON:" in out3
    assert "Routing Table of spoke after deletion" in out4
    assert "Not deleted route" in out5
