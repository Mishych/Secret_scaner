import requests
from urllib.parse import urlparse
import boto3
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

class SecretValidator:
    """
    A class for checking different types of secrets.
    """
    
    @staticmethod
    def validate_github_token(token: str):
        """
        Checks the validity of the GitHub token.
        """
        headers = {"Authorization": f"token {token}"}
        response = requests.get("https://api.github.com/user", headers=headers)
        if response.status_code == 200:
            return "VALID"
        else:
            return "INVALID: Cannot authenticate"

    @staticmethod
    def validate_aws_keys(access_key, secret_key):
        """
        Checks the validity of AWS access keys.
        """
        try:
            session = boto3.Session(aws_access_key_id=access_key, aws_secret_access_key=secret_key)
            session.client("sts").get_caller_identity()
            return "VALID"
        except (NoCredentialsError, PartialCredentialsError, Exception):
            return "INVALID: Cannot authenticate"

    @staticmethod
    def validate_slack_token(token: str):
        """
        Checks the validity of the Slack token.
        """
        response = requests.get("https://slack.com/api/auth.test", headers={"Authorization": f"Bearer {token}"})
        if response.status_code == 200 and response.json().get("ok"):
            return "VALID"
        else:
            return "INVALID: Cannot authenticate"
        
    @staticmethod   
    def validate_google_api_key(api_key: str) -> str:
        """
        Checks the validity of the Google API Key.
        """
        # URL для тестового запиту (наприклад, Geocoding API)
        test_url = "https://maps.googleapis.com/maps/api/geocode/json"
        params = {
            "address": "New York",  # Тестова адреса
            "key": api_key
        }

        try:
            response = requests.get(test_url, params=params)
            if response.status_code == 200:
                data = response.json()
                # Перевіряємо, чи є помилка, пов'язана з API Key
                if "error_message" in data:
                    return f"INVALID: {data['error_message']}"
                else:
                    return "VALID"
            else:
                return f"INVALID: HTTP {response.status_code}"
        except requests.RequestException as e:
            return f"Error: {e}"
        
    @staticmethod    
    def validate_uri_with_credentials(uri: str):
        parsed_uri = urlparse(uri)
        scheme = parsed_uri.scheme
        hostname = parsed_uri.hostname
        port = parsed_uri.port
        username = parsed_uri.username
        password = parsed_uri.password

        response = requests.get(f"{scheme}://{hostname}:{port}", auth=(username, password))
        
        if response.status_code == 200:
            return "VALID"
        else:
            return "INVALID: Cannot authenticate"
            