# lldap-py

Python client library for managing LLDAP servers  [lldap/lldap](https://github.com/lldap/lldap)

## Usage

This package provides a Python interface to interact with LLDAP servers for user and group management. The idea is that it would be used in an onboarding/offboarding automation script and make similar automation tasks easier.

### Quickstart
1. Install the package.
2. Create a `LLDAPManager` with your server URL and credentials.
3. Use the user and group helpers to perform actions.

```python
from lldap import LLDAPManager

manager = LLDAPManager(
	http_url="http://localhost:17170",
	username="admin",
	password="your-password",
	# Needed for LDAP password changes
	base_dn="dc=example,dc=com",
	ldap_server="ldap://localhost:3890",
)

users = manager.list_users()
groups = manager.list_groups()

user_id = "jdoe"
manager.create_user(
	user_id,
	"jdoe@example.com",
	"Jane Doe",
	"Jane",
	"Doe",
)

group_id = manager.get_group_id("BasicUserGroup")
if group_id is not None:
	manager.add_user_to_group(user_id, group_id)

# Requires base_dn and ldap_server
manager.set_password(user_id, "TempPassw0rd!")

manager.close()
```

Notes:
- You can authenticate with `token` or `refresh_token` instead of `username` and `password`.
- Set `verify_ssl=False` if you are connecting to a test server with self-signed certs.

### Installation
You can install the package via pip:

``` pip install lldap-py ```

https://pypi.org/project/lldap-py

## Requirements
- Python 3.8+
- requests
- ldap3
- toml
- click

## TODO
- Maybe improve error handling and passing of graphql errors to the user.
- Add more examples and documentation.
- Check coverage of tests
- Add support for costum user and group attributes.

## Credit
This project is heavely inspired by and uses alot of code from [Zepmann/lldap-cli](https://github.com/Zepmann/lldap-cli) and [JaidenW/LLDAP-Discord](https://github.com/JaidenW/LLDAP-Discord)


## License

MIT