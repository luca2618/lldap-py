import json
from typing import Optional, Dict, Any, Tuple
import requests
from .config import Config
from .exceptions import (
    AuthenticationError,
    ConnectionError,
    GraphQLError,
)


class LLDAPClient:
    """Client for interacting with LLDAP server via GraphQL API."""
    
    def __init__(self, config: Config):
        """Initialize LLDAP client.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.session = requests.Session()
        self._authenticated = False
    
    def authenticate(self) -> Tuple[str, str]:
        """Authenticate and get tokens.
        
        Returns:
            Tuple of (token, refresh_token)
            
        Raises:
            AuthenticationError: If authentication fails
            ConnectionError: If connection fails
        """
        if self.config.token:
            # Already have a token
            return self.config.token, self.config.refresh_token or ""
        
        if self.config.refresh_token:
            # Use refresh token to get new token
            token = self.refresh_token(self.config.refresh_token)
            self.config.token = token
            return token, self.config.refresh_token
        
        # Use username and password
        url = self.config.get_endpoint_url("auth")
        payload = {
            "username": self.config.username,
            "password": self.config.password,
        }
        
        try:
            response = self.session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                verify=self.config.verify_ssl,
            )
            
            if response.status_code != 200:
                raise AuthenticationError(f"Authentication failed: {response.text}")
            
            data = response.json()
            token = data.get("token")
            refresh_token = data.get("refreshToken")
            
            if not token:
                raise AuthenticationError("No token in response")
            
            self.config.token = token
            self.config.refresh_token = refresh_token
            self._authenticated = True
            
            return token, refresh_token
            
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {e}")
    
    def refresh_token(self, refresh_token: str) -> str:
        """Get a new token using refresh token.
        
        Args:
            refresh_token: Refresh token
            
        Returns:
            New authentication token
            
        Raises:
            AuthenticationError: If token refresh fails
            ConnectionError: If connection fails
        """
        url = self.config.get_endpoint_url("refresh")
        
        try:
            response = self.session.get(
                url,
                cookies={"refresh_token": refresh_token},
                verify=self.config.verify_ssl,
            )
            
            if response.status_code != 200:
                raise AuthenticationError(f"Token refresh failed: {response.text}")
            
            data = response.json()
            token = data.get("token")
            
            if not token:
                raise AuthenticationError("No token in refresh response")
            
            return token
            
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {e}")
    
    def logout(self) -> bool:
        """Logout and invalidate refresh token.
        
        Returns:
            True if successful
            
        Raises:
            ConnectionError: If connection fails
        """
        if not self.config.refresh_token:
            return False
        
        url = self.config.get_endpoint_url("logout")
        
        try:
            response = self.session.get(
                url,
                cookies={"refresh_token": self.config.refresh_token},
                verify=self.config.verify_ssl,
            )
            return response.status_code == 200
            
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {e}")
    
    def query(
        self,
        query: str,
        variables: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a GraphQL query.
        
        Args:
            query: GraphQL query string
            variables: Query variables
            
        Returns:
            GraphQL response data
            
        Raises:
            GraphQLError: If query returns errors
            ConnectionError: If connection fails
        """
        # Ensure we're authenticated
        if not self.config.token:
            self.authenticate()
        
        url = self.config.get_endpoint_url("graphql")
        
        payload = {
            "query": query,
            "variables": variables or {},
        }
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.token}",
        }
        
        data = json.dumps(payload)
        
        try:
            response = self.session.post(url, data=data, headers=headers, verify=self.config.verify_ssl)
            
            # Check for HTTP errors
            if response.status_code == 401:
                raise AuthenticationError(
                    "Authentication failed. Token may be expired. Try logging in again."
                )
            elif response.status_code != 200:
                raise ConnectionError(
                    f"HTTP {response.status_code}: {response.text}"
                )
            
            result = response.json()
            
            # Check for GraphQL errors
            if "errors" in result:
                error_messages = [err.get("message", str(err)) for err in result["errors"]]
                raise GraphQLError("; ".join(error_messages))
            
            return result
            
        except requests.RequestException as e:
            raise ConnectionError(f"Connection error: {e}")
    
    def ensure_authenticated(self) -> None:
        """Ensure client is authenticated, authenticate if not."""
        if not self.config.token:
            self.authenticate()
    
    def create_bind_dn(self, user_id: str) -> str:
        """Create bind DN for a user.
        
        Args:
            user_id: User ID """
        if self.config.base_dn is None:
            raise ValueError("base_dn is not configured")
        return f"uid={user_id},ou=people,{self.config.base_dn}"
    
    def ensure_ldap_connection(self) -> bool:
        from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
        if (self.config.ldap_server is not None) and (self.config.base_dn is not None):
            conn = None
            try:
                login_dn = self.create_bind_dn(self.config.username)
                server = Server(self.config.ldap_server, get_info=ALL)
                self.conn = Connection(server, login_dn, self.config.password, auto_bind=True)
            except Exception:
                return False
            return True
        return False


