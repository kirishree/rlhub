import pytest
import random
import ipaddress
from django.urls import reverse
from django.test import override_settings

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
        (ipaddress.IPv4Network("10.0.0.0/8"), 8),
        (ipaddress.IPv4Network("172.16.0.0/12"), 12),
        (ipaddress.IPv4Network("192.168.0.0/16"), 16),
    ]
    addroute = []
    for i in range(0,20):
        network_base, base_prefix = random.choice(private_ranges)
        prefix = random.randint(0,32)
        # Calculate how many networks of desired prefix fit in this base range
        max_subnets = 2 ** (prefix - base_prefix)
        subnet_index = random.randint(0, max_subnets - 1)        
        # Get the nth subnet of the desired prefix
        subnets = list(network_base.subnets(new_prefix=prefix))
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
    

