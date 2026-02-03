import pytest
from lldap import LLDAPManager, LLDAPClient, AuthenticationError, ConnectionError, ValidationError
from lldap.users import User
from lldap.groups import Group


@pytest.fixture(scope="session")
def manager_unsecure():
    """Manager instance for unsecure connection"""
    config = {
        "http_url": "http://localhost:17170",
        "username": "admin",
        "password": "password",
        "base_dn": "dc=example,dc=com",
        "ldap_server": "ldap://localhost:3890",
    }
    return LLDAPManager(**config)

@pytest.fixture(scope="session")
def manager_secure():
    """Manager instance for secure connection"""
    config = {
        "http_url": "https://localhost",  # Different endpoint
        "username": "admin",
        "password": "password",
        "base_dn": "dc=example,dc=com",
        "ldap_server": "ldaps://localhost:6360",  # Using LDAPS
        "verify_ssl": False, # Disable SSL verification for testing
    }
    return LLDAPManager(**config)

@pytest.fixture(scope="session", params=["unsecure", "secure"])
def manager(request):
    """Parametrized manager fixture."""
    if request.param == "unsecure":
        return request.getfixturevalue("manager_unsecure")
    else:
        return request.getfixturevalue("manager_secure")


@pytest.fixture(scope="session", autouse=True)
def cleanup_before_tests(manager):
    """Clean up existing test data before running tests."""
    # Clean up any existing test users
    for user in manager.list_users():
        if user.user_id != "admin" and user.user_id.startswith("test"):
            manager.delete_user(user.user_id)

    # Clean up any existing test groups
    for group in manager.list_groups():
        if group.display_name.startswith("test"):
            manager.delete_group(group.display_name)
    
    yield
    
    # Cleanup after all tests
    for user in manager.list_users():
        if user.user_id != "admin" and user.user_id.startswith("test"):
            manager.delete_user(user.user_id)
    
    for group in manager.list_groups():
        if group.display_name.startswith("test"):
            manager.delete_group(group.display_name)


# ========== Connection and Authentication Tests ==========

def test_connection(manager):
    """Test the connection to the LLDAP server."""
    assert isinstance(manager.client, LLDAPClient)


def test_authentication(manager):
    """Test authentication with valid credentials."""
    try:
        token, refresh_token = manager.client.authenticate()
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    except (AuthenticationError, ConnectionError):
        pytest.fail("Authentication or connection failed with valid credentials.")


# ========== User Management Tests ==========

def test_create_user_basic(manager):
    """Test creating a user with basic information."""
    result = manager.create_user(
        user_id="testuser1",
        email="testuser1@test.com",
        first_name="Test",
        last_name="User1",
    )
    
    assert result is not None
    assert result.get("id") == "testuser1"
    assert result.get("email") == "testuser1@test.com"
    
    # Verify user exists in list
    users = manager.list_users()
    user_ids = [user.user_id for user in users]
    assert "testuser1" in user_ids


def test_create_user_with_display_name(manager):
    """Test creating a user with custom display name."""
    result = manager.create_user(
        user_id="testuser2",
        email="testuser2@test.com",
        display_name="Custom Display Name",
        first_name="Test",
        last_name="User2",
    )
    
    assert result.get("displayName") == "Custom Display Name"


def test_list_users(manager):
    """Test listing all users."""
    users = manager.list_users()
    
    assert isinstance(users, list)
    assert len(users) > 0
    
    # Verify all items are User objects
    for user in users:
        assert isinstance(user, User)
        assert hasattr(user, 'user_id')
        assert hasattr(user, 'email')
        assert hasattr(user, 'display_name')
        assert hasattr(user, 'first_name')
        assert hasattr(user, 'last_name')


def test_get_user_id_by_email(manager):
    """Test getting user ID by email address."""
    # Test with existing user
    user_id = manager.get_user_id_by_email("testuser1@test.com")
    assert user_id == "testuser1"
    
    # Test with non-existent user
    user_id = manager.get_user_id_by_email("nonexistent@test.com")
    assert user_id is None


def test_list_user_attributes(manager):
    """Test listing user attributes."""
    attributes = manager.list_user_attributes("testuser1")
    
    assert isinstance(attributes, list)
    # Attributes should be sorted
    assert attributes == sorted(attributes)


def test_delete_user(manager):
    """Test deleting a user."""
    # Create a user to delete
    manager.create_user(
        user_id="testuser_todelete",
        email="delete@test.com",
        first_name="Delete",
        last_name="Me",
    )
    
    # Verify user exists
    assert "testuser_todelete" in [u.user_id for u in manager.list_users()]
    
    # Delete the user
    result = manager.delete_user("testuser_todelete")
    assert result is True
    
    # Verify user is gone
    assert "testuser_todelete" not in [u.user_id for u in manager.list_users()]


# ========== Group Management Tests ==========

def test_create_group(manager):
    """Test creating a group."""
    result = manager.create_group(name="testgroup1")
    
    assert result is not None
    assert "id" in result
    
    # Verify group exists
    group_id = manager.get_group_id(name="testgroup1")
    assert group_id is not None


def test_list_groups(manager):
    """Test listing all groups."""
    groups = manager.list_groups()
    
    assert isinstance(groups, list)
    assert len(groups) > 0
    
    # Verify all items are Group objects
    for group in groups:
        assert isinstance(group, Group)
        assert hasattr(group, 'groupid')
        assert hasattr(group, 'display_name')
        assert hasattr(group, 'uuid')
        assert hasattr(group, 'creation_date')


def test_get_group_id_by_name(manager):
    """Test getting group ID by name."""
    # Test with existing group
    group_id = manager.get_group_id(name="testgroup1")
    assert group_id is not None
    assert isinstance(group_id, int)
    
    # Test with non-existent group
    group_id = manager.get_group_id(name="nonexistent_group")
    assert group_id is None


def test_fetch_group_by_id(manager):
    """Test fetching a group by its ID."""
    # Get a known group ID
    group_id = manager.get_group_id(name="testgroup1")
    
    # Fetch by ID
    group = manager.fetch_group_by_id(group_id)
    assert group is not None
    assert isinstance(group, Group)
    assert group.groupid == group_id
    assert group.display_name == "testgroup1"
    
    # Test with non-existent ID
    group = manager.fetch_group_by_id(999999)
    assert group is None



def test_delete_group_by_name(manager):
    """Test deleting a group by name."""
    # Create a group to delete
    manager.create_group(name="testgroup_todelete")
    
    # Verify group exists
    assert manager.get_group_id(name="testgroup_todelete") is not None
    
    # Delete by name
    result = manager.delete_group("testgroup_todelete")
    assert result is True
    
    # Verify group is gone
    assert manager.get_group_id(name="testgroup_todelete") is None


def test_delete_group_by_id(manager):
    """Test deleting a group by ID."""
    # Create a group to delete
    manager.create_group(name="testgroup_todelete2")
    group_id = manager.get_group_id(name="testgroup_todelete2")
    
    # Delete by ID
    result = manager.delete_group(group_id)
    assert result is True
    
    # Verify group is gone
    assert manager.get_group_id(name="testgroup_todelete2") is None


def test_delete_group_invalid_type(manager):
    """Test that deleting a group with invalid type raises ValidationError."""
    with pytest.raises(ValidationError):
        manager.delete_group(12.34)  # Float is not valid


def test_delete_nonexistent_group(manager):
    """Test deleting a non-existent group raises ValidationError."""
    with pytest.raises(ValidationError):
        manager.delete_group("nonexistent_group_xyz")


# ========== User-Group Relationship Tests ==========

def test_add_user_to_group(manager):
    """Test adding a user to a group."""
    # Create test user and group
    manager.create_user(
        user_id="testuser_group",
        email="testuser_group@test.com",
        first_name="Group",
        last_name="Test",
    )
    manager.create_group(name="testgroup_members")
    group_id = manager.get_group_id(name="testgroup_members")
    
    # Add user to group
    result = manager.add_user_to_group(user_id="testuser_group", group_id=group_id)
    assert result is True
    
    # Verify user is in group
    user_groups = manager.list_user_groups(user_id="testuser_group")
    assert "testgroup_members" in user_groups


def test_list_user_groups(manager):
    """Test listing groups that a user belongs to."""
    groups = manager.list_user_groups(user_id="testuser_group")
    
    assert isinstance(groups, list)
    assert "testgroup_members" in groups


def test_list_group_users_by_name(manager):
    """Test listing users in a group by group name."""
    users = manager.list_group_users("testgroup_members")
    
    assert isinstance(users, list)
    user_ids = [user.user_id for user in users]
    assert "testuser_group" in user_ids


def test_list_group_users_by_id(manager):
    """Test listing users in a group by group ID."""
    group_id = manager.get_group_id(name="testgroup_members")
    users = manager.list_group_users(group_id)
    
    assert isinstance(users, list)
    user_ids = [user.user_id for user in users]
    assert "testuser_group" in user_ids


def test_remove_user_from_group(manager):
    """Test removing a user from a group."""
    group_id = manager.get_group_id(name="testgroup_members")
    
    # Verify user is in group first
    group_user_ids = [u.user_id for u in manager.list_group_users(group_id)]
    assert "testuser_group" in group_user_ids
    
    # Remove user from group
    result = manager.remove_user_from_group(user_id="testuser_group", group_id=group_id)
    assert result is True
    
    # Verify user is no longer in group
    user_groups = manager.list_user_groups(user_id="testuser_group")
    assert "testgroup_members" not in user_groups
    
    # Verify group doesn't list the user
    group_users = manager.list_group_users(group_id)
    group_user_ids = [u.user_id for u in group_users]
    assert "testuser_group" not in group_user_ids


# ========== Integration Tests ==========

def test_full_user_lifecycle(manager):
    """Test complete user lifecycle: create, modify memberships, delete."""
    # Create user
    manager.create_user(
        user_id="testuser_lifecycle",
        email="lifecycle@test.com",
        first_name="Lifecycle",
        last_name="Test",
    )
    
    # Verify creation
    assert "testuser_lifecycle" in [u.user_id for u in manager.list_users()]
    
    # Create groups and add user
    manager.create_group(name="testgroup_lifecycle1")
    manager.create_group(name="testgroup_lifecycle2")
    
    group1_id = manager.get_group_id(name="testgroup_lifecycle1")
    group2_id = manager.get_group_id(name="testgroup_lifecycle2")
    
    manager.add_user_to_group("testuser_lifecycle", group1_id)
    manager.add_user_to_group("testuser_lifecycle", group2_id)
    
    # Verify memberships
    user_groups = manager.list_user_groups("testuser_lifecycle")
    assert "testgroup_lifecycle1" in user_groups
    assert "testgroup_lifecycle2" in user_groups
    
    # Remove from one group
    manager.remove_user_from_group("testuser_lifecycle", group1_id)
    user_groups = manager.list_user_groups("testuser_lifecycle")
    assert "testgroup_lifecycle1" not in user_groups
    assert "testgroup_lifecycle2" in user_groups
    
    # Delete user
    manager.delete_user("testuser_lifecycle")
    assert "testuser_lifecycle" not in [u.user_id for u in manager.list_users()]
    
    # Cleanup groups
    manager.delete_group("testgroup_lifecycle1")
    manager.delete_group("testgroup_lifecycle2")


def test_full_group_lifecycle(manager):
    """Test complete group lifecycle: create, add users, remove users, delete."""
    # Create group
    manager.create_group(name="testgroup_fullcycle")
    group_id = manager.get_group_id(name="testgroup_fullcycle")
    assert group_id is not None
    
    # Create users
    manager.create_user(
        user_id="testuser_cycle1",
        email="cycle1@test.com",
        first_name="Cycle",
        last_name="One",
    )
    manager.create_user(
        user_id="testuser_cycle2",
        email="cycle2@test.com",
        first_name="Cycle",
        last_name="Two",
    )
    
    # Add users to group
    manager.add_user_to_group("testuser_cycle1", group_id)
    manager.add_user_to_group("testuser_cycle2", group_id)
    
    # Verify members
    members = manager.list_group_users(group_id)
    member_ids = [u.user_id for u in members]
    assert "testuser_cycle1" in member_ids
    assert "testuser_cycle2" in member_ids
    
    # Remove one user
    manager.remove_user_from_group("testuser_cycle1", group_id)
    members = manager.list_group_users(group_id)
    member_ids = [u.user_id for u in members]
    assert "testuser_cycle1" not in member_ids
    assert "testuser_cycle2" in member_ids
    
    # Delete group
    manager.delete_group(group_id)
    assert manager.get_group_id(name="testgroup_fullcycle") is None
    
    # Cleanup users
    manager.delete_user("testuser_cycle1")
    manager.delete_user("testuser_cycle2")


# ========== Password Management Tests ==========

def test_set_password_and_login(manager):
    """Test setting password for a new user and logging in with it."""
    # Create a new test user
    user_id = "testuser_password"
    test_password = "TestPassword123!@#"
    
    result = manager.create_user(
        user_id=user_id,
        email="testuser_password@test.com",
        first_name="Password",
        last_name="Test",
    )
    
    assert result is not None
    assert result.get("id") == user_id
    
    # Set password for the user
    password_set = manager.set_password(user_id, test_password)
    assert password_set is True
    
    # Try to authenticate with the new user credentials
    from lldap import LLDAPManager
    new_manager = LLDAPManager(
        http_url= manager.config.http_url,
        username=user_id,
        password=test_password,
        base_dn= manager.config.base_dn,
        ldap_server= manager.config.ldap_server,
        verify_ssl= manager.config.verify_ssl
    )


    try:
        token, refresh_token = new_manager.client.authenticate()
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    except (AuthenticationError, ConnectionError):
        pytest.fail(f"Failed to authenticate with user {user_id} after setting password")
    assert new_manager.client.ensure_ldap_connection() is True
    # Cleanup
    manager.delete_user(user_id)

    
