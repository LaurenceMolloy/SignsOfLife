import requests
from base64 import b64encode
from nacl import encoding, public
from dotenv import load_dotenv, dotenv_values
from typing import Dict


# NB: this script requires read & write repository permissions for Secrets
#     and Variables to be set for the GitHub Token that is used

# Load .env file
load_dotenv()
env_vars = dotenv_values()  # Get env vars as a dictionary

# Remove all GITHUB_* named secrets and variables (these don't get written to repo)
env_vars_filtered = {
    key: val for key, val in env_vars.items() if not key.startswith("GITHUB_")
}

# Classify filtered environment vars as secrets or repository variables
sensitive_keywords = {"PASSWORD", "EMAIL", "KEY", "TOKEN", "SECRET"}
secrets = {k: v for k, v in env_vars_filtered.items() if any(word in k for word in sensitive_keywords)}
vars = {k: v for k, v in env_vars_filtered.items() if k not in secrets.keys()}

GITHUB_API_URL = f"https://api.github.com/repos/{vars['REPO_OWNER']}/{vars['REPO_NAME']}"
HEADERS = {
    "Authorization": f"Bearer {env_vars['GITHUB_TOKEN']}",
    "Accept": "application/vnd.github.v3+json",
    "X-GitHub-Api-Version": "2022-11-28"
}


def clear_variables() -> None:
    """Clear all existing repository variables."""
    url = f"{GITHUB_API_URL}/actions/variables"
    response = requests.get(url, headers=HEADERS)
    github_repo_vars = [var['name'] for var in response.json()['variables']]
    
    for var in github_repo_vars:
        url = f"{GITHUB_API_URL}/actions/variables/{var}"
        response = requests.delete(url, headers=HEADERS)
        
        if response.status_code in [201, 204]:
            print(f"Variable '{var}' has been deleted.")
        else:
            print(f"Failed to delete variable '{var}': {response.json()}")


def clear_secrets() -> None:
    """Clear all existing repository secrets."""
    secret_url = f"{GITHUB_API_URL}/actions/secrets"
    response = requests.get(secret_url, headers=HEADERS)
    github_secrets = [secret['name'] for secret in response.json()['secrets']]
    
    for secret in github_secrets:
        secret_url = f"{GITHUB_API_URL}/actions/secrets/{secret}"
        response = requests.delete(secret_url, headers=HEADERS)
        
        if response.status_code in [201, 204]:
            print(f"Secret '{secret}' has been deleted.")
        else:
            print(f"Failed to delete secret '{secret}': {response.json()}")


def create_variable(name: str, value: str) -> None:
    """Create a repository variable."""
    url = f"{GITHUB_API_URL}/actions/variables"
    payload = {"name": name, "value": value}
    response = requests.post(url, headers=HEADERS, json=payload)
    
    if response.status_code in [201, 204]:
        print(f"Variable '{name}' created.")
    else:
        print(f"Failed to create variable '{name}': {response.json()}")


def encrypt(public_key: str, secret_value: str) -> str:
    """Encrypt a Unicode string using the public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
    return b64encode(encrypted).decode("utf-8")


def create_secret(name: str, value: str) -> None:
    """Create a repository secret."""
    # Get public key for encrypting the secret
    key_response = requests.get(f"{GITHUB_API_URL}/actions/secrets/public-key", headers=HEADERS)
    
    if key_response.status_code != 200:
        print(f"Failed to fetch public key: {key_response.json()}")
        return

    key = key_response.json()
    public_key = key['key']
    key_id = key['key_id']
    
    # Create encrypted secret
    secret_url = f"{GITHUB_API_URL}/actions/secrets/{name}"
    payload = {
        "encrypted_value": encrypt(public_key, value),
        "key_id": key_id
    }
    response = requests.put(secret_url, headers=HEADERS, json=payload)
    
    if response.status_code in [201, 204]:
        print(f"Secret '{name}' created.")
    else:
        print(f"Failed to create secret '{name}': {response.json()}")


def main() -> None:
    """Main function to clear and recreate variables and secrets."""
    # Clear down & re-create repository variables
    clear_variables()
    for key, value in vars.items():
        create_variable(key, value)

    # Clear down & re-create repository secrets
    clear_secrets()
    for key, value in secrets.items():
        create_secret(key, value)


if __name__ == "__main__":
    main()
