import pytest
from django.urls import reverse
from django.test import override_settings

@override_settings(SECURE_SSL_REDIRECT=False)
@pytest.mark.django_db
def test_branch_info_view_with_token(client):
    # Step 1: Login to get access token
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_data = {
        "username": "xogaw4457@edectus.com",
        "password": "xogaw4457@edectus.com"
    }
    login_response = client.post(login_url, login_data, content_type="application/json")
    assert login_response.status_code == 200
    print("Login response JSON:", login_response.json())
    token = login_response.json().get("access")  # Adjust this if your token key is different
    assert token is not None

    # Step 2: Call branch_info with Authorization header
    headers = {
        "HTTP_AUTHORIZATION": f"Bearer {token}"
    }
    branch_info_url = reverse("branch_info") + "?organization_id=ea318b0108d6495babfbd020ffc4e132"
    response = client.get(branch_info_url, **headers)

    assert response.status_code == 200
    json_data = response.json()

    # Optional: Assert fields in response
    assert "total_branches" in json_data
    assert "organization_id" in json_data

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
def test_login(client, payload, expected):
    login_url = reverse("login_or_register")  # or use hardcoded '/api/auth/'
    login_response = client.post(login_url, payload, content_type="application/json")    
    assert login_response.status_code == expected