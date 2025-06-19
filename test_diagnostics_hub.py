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

testpoint = "login_info"
cases = []
cases.append(pytest.param({  "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
        }, 200, id=f"{testpoint}:xogaw4457@edectus.com"))
cases.append(pytest.param({"username": "cejavak731@wermink.com",
      "password": "cejavak731@wermink.com"
      }, 200, id=f"{testpoint}:cejavek731@wermink.com"))
cases.append(pytest.param({
        "username": "xogaw4457@edectus.com",
        "password": "invalidpassword"
    }, 400, id=f"{testpoint}:Invalid Password"))
cases.append(pytest.param({
        "username": "xogaw@edectus.com",
        "password": "xogaw4457@edectus.com"
    }, 400, id=f"{testpoint}:Invalid Login"))    
cases.append(pytest.param({"password": "xogaw@edectus.com" }, 400, id=f"{testpoint}:Username missed"))
cases.append(pytest.param({"username": "xogaw@edectus.com" }, 400, id=f"{testpoint}:Password missed"))
cases.append(pytest.param({ }, 400, id=f"{testpoint}:Login missed"))


@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.parametrize("login_data,expected", cases)
@pytest.mark.django_db
def test_ping_hub(client, capfd, login_data, expected):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'    
    logger.info(f"Login info: {login_data}")
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == expected
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr()
    logger.info(f"login response: {login_response.json()}")
    token = login_response.json().get("access")  # Adjust this if your token key is different
    if token is not None:
        # Step 2: Call branch_info with Authorization header
        headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
        }
        #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
        ping_hub_url = reverse("diagnostics")
        payload = {"hub_wan_ip":"185.69.209.251",
                   "uuid":"reachlinkserver.net",
                   "subnet":"8.8.8.8"}
        logger.info(f"Testing ping from hub: {payload}")
        response = client.post(ping_hub_url,  payload, content_type="application/json", **headers)
        json_data = response.json() 
        logger.info(f"Ping response from HUB: {json_data}")
        assert response.status_code == expected    
        assert "Error" not in json_data[0]["message"]

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.parametrize("login_data,expected", cases)
@pytest.mark.django_db
def test_tarceroute_hub(client, capfd, login_data, expected):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'    
    logger.info(f"Login info: {login_data}")
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == expected
    print("Login response JSON:", login_response.json())
    # Capture output after print
    out, err = capfd.readouterr()
    logger.info(f"login response: {login_response.json()}")
    token = login_response.json().get("access")  # Adjust this if your token key is different
    if token is not None:
        # Step 2: Call branch_info with Authorization header
        headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
        }
        #branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
        traceroute_hub_url = reverse("traceroute_hub")
        payload = {"hub_wan_ip":"185.69.209.251",
                   "uuid":"reachlinkserver.net",
                   "trace_ip":"8.8.8.8"}
        logger.info(f"Testing trace from hub: {payload}")
        response = client.post(traceroute_hub_url,  payload, content_type="application/json", **headers)
        json_data = response.json() 
        logger.info(f"Trace response from HUB: {json_data}")
        assert response.status_code == expected    
        assert "Error" not in json_data[0]["message"]

