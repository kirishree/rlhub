import pytest
import pytest_html

# Hook to inject extra into report
@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    extra = getattr(item, "extra", [])
    report.extras = extra

# Fixture to allow test case to collect extras
@pytest.fixture
def extra(request):
    request.node.extra = []
    return request.node.extra
