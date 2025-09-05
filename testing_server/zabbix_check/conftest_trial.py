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
    report = outcome.get_result()
    extras = getattr(report, "extras", [])
    # Only add extra info on the actual test call (not setup/teardown)
    #if rep.when == "call":
    if report.when == "call":
        extras.append(pytest_html.extras.text("some string", name="Different title"))        
        # Attach to report
        report.extras = extras

# Fixture to collect 'extra' content
@pytest.fixture
def extra(request):
    request.node.extra = []
    return request.node.extra

import pytest

@pytest.hookimpl(tryfirst=True)
def pytest_runtest_makereport(item, call):
    if call.when == "call" and call.excinfo is not None:
        # Example: Attach a screenshot or log file
        extra = getattr(item, 'extra', [])
        extra.append(pytest_html.extras.text("Additional info"))
        item.extra = extra

