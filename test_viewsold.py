import pytest
import random
import ipaddress
from django.urls import reverse
from django.test import override_settings
import time
import json
from pytest_html import extras

import tempfile
import os
import base64
from io import BytesIO
from PIL import Image, ImageDraw, ImageFont

def generate_image_with_text(text):
    lines = text.splitlines()
    font = ImageFont.load_default()
    # Estimate image size
    width = max(font.getbbox(line)[2] for line in lines) + 20
    height = (font.getbbox("Test")[3] + 5) * len(lines) + 20

    image = Image.new("RGB", (width, height), (255, 255, 255))
    draw = ImageDraw.Draw(image)

    y = 10
    for line in lines:
        draw.text((10, y), line, font=font, fill=(0, 0, 0))
        y += font.getbbox(line)[3] + 5

    buffer = BytesIO()
    image.save(buffer, format="PNG")
    base64_image = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return base64_image

def generate_image_with_text1(text):
    img = Image.new("RGB", (800, 200), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    font = ImageFont.load_default()
    draw.text((10, 10), text, fill="black", font=font)

    # Save to buffer
    buffer = BytesIO()
    img.save(buffer, format="PNG")
    buffer.seek(0)
    # Base64 encode the image data
    encoded_image = base64.b64encode(buffer.read()).decode("utf-8")  # MUST decode to str!
    return encoded_image

def text_to_image(text, font_size=14):
    font = ImageFont.load_default()  # You can use truetype fonts too
    lines = text.split('\n')

    # Calculate max width and total height
    line_heights = []
    line_widths = []

    for line in lines:
        bbox = font.getbbox(line)
        line_width = bbox[2] - bbox[0]
        line_height = bbox[3] - bbox[1]
        line_widths.append(line_width)
        line_heights.append(line_height)

    width = max(line_widths) + 20
    height = sum(line_heights) + 20

    image = Image.new("RGB", (width, height), "white")
    draw = ImageDraw.Draw(image)

    y = 10
    for i, line in enumerate(lines):
        draw.text((10, y), line, fill="black", font=font)
        y += line_heights[i]

    temp_path = os.path.join(tempfile.gettempdir(), "output_image.png")
    image.save(temp_path)
    return temp_path

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
def test_login_response(client, capfd, extra):
    login_url = reverse("login_or_register") 
    response = client.post(login_url, {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }, content_type="application/json")

    assert response.status_code == 200

    output = response.json()  # list or dict
    pretty_text = json.dumps(output, indent=2)

    # Print to console (optional)
    print("Formatted Output:\n", pretty_text)

    # Convert to image
    img_path = text_to_image(pretty_text)

    # Attach image to pytest-html report
    with open(img_path, "rb") as img_file:
        #extra.append(extras.image(img_file.read(), name="Output Screenshot"))
        extra.append(extras.image(img_file.read(), mime_type="image/png", extension="png"))
    #img_base64 = generate_image_with_text(pretty_text)
    #extra.append(extras.image(img_base64, mime_type="image/png", extension="png"))
    # Cleanup if needed
    #os.remove(img_path)

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
    #extra.append(extras.text(json.dumps(login_response.json(), indent=2), name="Login response JSON:"))
    extras.append(extras.json(login_response.json(), name="Login response"))
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
    #extra.append(extras.text(json.dumps(addroute.json(), indent=2), name="Randomly Generated routes"))
    extras.append(extras.json(addroute, name="Randomly Generated routes"))
    addstaticroute_hub_url = reverse("add_route_spoke")
    response = client.post(addstaticroute_hub_url, addroute_data, content_type="application/json", **headers)

    assert response.status_code == 200
    json_data = response.json()
    print("Add Route Spoke response JSON:", response.json())
    # Capture output after print
    out2, err = capfd.readouterr() 
    #extra.append(extras.text(out2, name="Add Route Spoke response JSON:"))
    extras.append(extras.json(response.json(), name="Add Route Spoke response"))
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
    print("Routing Table after added routes", routing_table)
    # Capture output after print
    out2, err = capfd.readouterr() 
    #extra.append(extras.text(json.dumps(response.json(), indent=2), name="Routing Table after added routes"))
    extras.append(extras.json(response.json(), name="Routing Table after added routes"))
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
        #extra.append(extras.text(json.dumps(routenotadded.json(), indent=2), name="Not Added Route checked by validation"))
        extras.append(extras.json(routenotadded.json(), name="Not Added Route checked by validation"))
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
    #extras.append(extras.text(json.dumps(login_response.json(), indent=2), name="Login response JSON:"))
    extra.append(extras.text(out, name="Login response"))
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
    print("Routing table of Spoke", routing_table)
    # Capture again
    out2, err2 = capfd.readouterr()
    #extras.append(extras.text(json.dumps(response.json(), indent=2), name="Routing table of Spoke before delete"))
    extra.append(extras.text(out2, name="Routing table of Spoke before delete"))
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
    #extras.append(extras.text(json.dumps(response.json(), indent=2), name="Delete Route response"))
    extra.append(extras.text(out3, name="Delete Route response"))
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
    #extras.append(extras.text(out4, name="Routing Table of spoke after deletion"))
    extra.append(extras.text(out4, name="Routing Table of spoke after deletion"))
    routenotdeleted = []
    for delinfo in deleteroute:        
        for routeinfo in  routing_table:
            if delinfo["destination"] == routeinfo["destination"]:                
                routenotdeleted.append(delinfo)
                break               
    print("Not deleted routes", routenotdeleted)
     # Capture output after print
    out5, err5 = capfd.readouterr() 
    extra.append(extras.text(out5, name="Not deleted routes"))
    #extras.append(extras.text(out5, name="Not deleted routes"))
    assert len(routenotdeleted) == 0
    # Optionally assert that captured output has expected text (optional)
    