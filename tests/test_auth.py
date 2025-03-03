import pytest
from unittest.mock import MagicMock, patch
from auth import Authenticator
from constants import SECURITY, SESSION_STATES
from time import time


@pytest.fixture
def mock_db(mocker):
    return mocker.MagicMock()


@pytest.fixture
def mock_encryptor(mocker):
    return mocker.MagicMock()


@pytest.fixture
def mock_logger(mocker):
    return mocker.MagicMock()


@pytest.fixture
def auth(mock_db, mock_encryptor, mock_logger):
    # Return an instance of Authenticator with the mocked dependencies
    auth = Authenticator.__new__(Authenticator)
    auth.db = mock_db
    auth.encryptor = mock_encryptor
    auth.logger = mock_logger
    auth.session_end = time()
    return auth


def test_authenticate_success(auth, mock_db, mock_encryptor, mock_logger):
    # Mock the behavior of the database and encryptor
    mock_db.get_by_username.return_value = ["hashed_password"]
    mock_encryptor.verify_master_password.return_value = True

    # Test successful authentication
    result = auth.authenticate("user1", "correct_password")

    # Assertions to check if the result is as expected
    assert result is True
    mock_db.get_by_username.assert_called_once_with("user1")
    mock_encryptor.verify_master_password.assert_called_once_with(
        "hashed_password", "correct_password"
    )
    mock_logger.log_auth_event.assert_called_once_with("user1", "login", True)


def test_authenticate_failure(auth, mock_db, mock_encryptor):
    # Mock the behavior of the database and encryptor
    mock_db.get_by_username.return_value = None
    mock_encryptor.verify_master_password.return_value = False

    # Test failed authentication
    result = auth.authenticate("user1", "wrong_password")

    # Assertions to check if the result is as expected
    assert result == "Invalid username or password"


def test_register_success(auth, mock_db, mock_encryptor, mock_logger):
    # Mock the behavior of the encryptor
    mock_encryptor.password_hash.return_value = "hashed_password"

    # Mock the behavior of the database add_pwd method
    mock_db.add_pwd.return_value = None  # Simulate successful registration

    # Test successful registration
    result = auth.register("user1", "password")

    # Assertions
    assert result is True
    mock_db.add_pwd.assert_called_once_with("user1", "hashed_password")
    mock_logger.log_auth_event.assert_called_once_with("user1", "register", True)


def test_register_failure_username_exists(auth, mock_db, mock_logger):
    # Mock the database to simulate username already exists
    mock_db.add_pwd.side_effect = FileExistsError("Username already exists")

    # Test registration failure due to username already existing
    result = auth.register("user1", "password")

    # Assertions
    assert result == "Username already exists"
    mock_logger.log_auth_event.assert_called_once_with("user1", "register", False)


def test_check_session_status_no_session(auth, mock_db, mock_encryptor, mock_logger):
    # Mock the check_session method to return None
    auth.check_session = MagicMock(return_value=None)

    # Test session status when there is no session
    result = auth.check_session_status()

    # Assertions
    assert result == "no_session"


def test_check_session_status_expired(auth, mock_db, mock_encryptor, mock_logger):
    # Mock the check_session method to simulate expired session
    auth.check_session = MagicMock(return_value=["user1", 0, 1, "ACTIVE"])

    # Mock time to be greater than session_end
    with patch("auth.time", return_value=2):  # Use proper path
        result = auth.check_session_status()

    assert result == SESSION_STATES["EXPIRED"]


def test_extend_session(auth, mock_db, mock_encryptor, mock_logger):
    # Mock the session data
    auth.check_session = MagicMock(return_value=["user1", 0, 1, "ACTIVE"])
    auth.update_session_file = MagicMock()  # Mock file update method

    # Test session extension
    result = auth.extend_session()

    # Assertions
    assert result is True
    auth.update_session_file.assert_called_once()


def test_end_session(auth, mock_db, mock_encryptor, mock_logger):
    # Mock the check_session method to simulate active session
    auth.check_session = MagicMock(return_value=["user1", 0, 1, "ACTIVE"])

    # Mock the scramble_session_file method to avoid actual file operations
    auth.scramble_session_file = MagicMock()

    # Test session ending
    result = auth.end_session()

    # Assertions
    assert result == "Session ended successfully"
    auth.scramble_session_file.assert_called_once()
    mock_logger.log_auth_event.assert_called_once_with("user1", "logout", True)
