import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--email", action="store", help="Zepp account email for integration tests")
    parser.addoption(
        "--password", action="store", help="Zepp account password for integration tests"
    )


@pytest.fixture
def zepp_email(request: pytest.FixtureRequest) -> str:
    val = request.config.getoption("--email")
    if not val:
        pytest.skip("--email not provided")
    return val


@pytest.fixture
def zepp_password(request: pytest.FixtureRequest) -> str:
    val = request.config.getoption("--password")
    if not val:
        pytest.skip("--password not provided")
    return val
