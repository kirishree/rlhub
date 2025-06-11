# conftest.py
import base64  
import os  
import pytest  
import pytest_html  
from pytest_metadata.plugin import metadata_key  
  

# Required for pytest-html to inject extra content into reports
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    # Execute all other hooks to obtain the report object
    outcome = yield
    rep = outcome.get_result()

    # Only add extra info on the actual test call (not setup/teardown)
    if rep.when == "call":
        # Get the extra list from the test context (if present)
        extra = getattr(rep, 'extra', [])

        # Attach to report
        rep.extra = extra

# Fixture to collect 'extra' content
@pytest.fixture
def extra(request):
    request.node.extra = []
    return request.node.extra
