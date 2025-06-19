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
@pytest.mark.parametrize("payload, expected", [({"tunnel_ip": "10.8.0.19", 
                    "uuid": "microtek21_microtek.net"}, 200)])
def test_deactivate(client, capfd, auth_token, payload, expected):   

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {auth_token}"
    }  
    deactivate_url = reverse("deactivate")
    logger.info(f"Testing for deactivation of {payload}")
    response = client.post(deactivate_url,  payload, content_type="application/json", **headers)
    assert response.status_code == expected
    json_data = response.json() 
    logger.info(f"Deactivation response: {json_data}")
    assert "Error" not in json_data[0]["message"]
    branch_info_url = reverse("branch_info")
    logger.info(f"Validating by getting branch info")
    response = client.get(branch_info_url, content_type="application/json", **headers)
    assert response.status_code == expected
    json_data = response.json() 
    logger.info(f"Branch info after deactivating. {json_data}")
    for device in json_data["data"]:
        if device["uuid"] == payload["uuid"]:
            assert device["status"] == "inactive" 
    logger.info(f"Validated. Branch deactivated successfully")
    