import argparse
import requests


from multiprocessing.dummy import Pool as ThreadPool
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

PROFILE_SUFFIX = "devesecops"

class SonarQubeAPI:
    def __init__(self):
        self.base_url = BASE_URL
        # This sonarqube is for internal use only, password not required.
        self.auth = (SQ_USERNAME, SQ_PASSWORD)
        self.session = self._create_session()

    def _create_session(self):
        session = requests.Session()
        retries = Retry(total=5, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('http://', HTTPAdapter(max_retries=retries))
        return session

    def _request_post(self, endpoint, data):
        try:
            response = self.session.post(endpoint, data=data, auth=self.auth)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            return None

    def create_quality_profile(self, language):
        endpoint = f"{self.base_url}/api/qualityprofiles/create"
        data = {
            "language": language,
            "name": f"{language}-{PROFILE_SUFFIX}"
        }
        response = self._request_post(endpoint, data)
        if response:
            return response.json().get("profile", {}).get("key")
        else:
            print(f"Failed to create quality profile for {language}.")
            return None

    def change_parent_quality_profile(self, language, profile_key):
        endpoint = f"{self.base_url}/api/qualityprofiles/change_parent"
        data = {
            "language": language,
            "qualityProfile": f"{language}-{PROFILE_SUFFIX}",
            "parentQualityProfile": "Sonar way"
        }
        self._request_post(endpoint, data)

    def deactivate_all_rules(self, profile_key):
        endpoint = f"{self.base_url}/api/qualityprofiles/deactivate_rules"
        data = {
            "activation": "true",
            "qprofile": profile_key,
            "targetKey": profile_key
        }
        self._request_post(endpoint, data)

    def activate_security_rules(self, profile_key):
        endpoint = f"{self.base_url}/api/qualityprofiles/activate_rules"
        data = {
            "activation": "false",
            "qprofile": profile_key,
            "statuses": "READY",
            "sonarsourceSecurity": ",".join([
                "buffer-overflow", "sql-injection", "rce", "object-injection",
                "command-injection", "path-traversal-injection", "ldap-injection",
                "xpath-injection", "log-injection", "xxe", "xss", "dos", "ssrf",
                "csrf", "http-response-splitting", "open-redirect", "weak-cryptography",
                "auth", "insecure-conf", "file-manipulation", "encrypt-data",
                "traceability", "permission", "others"
            ]),
            "targetKey": profile_key
        }
        self._request_post(endpoint, data)

    def setup_quality_profile(self, language):
        profile_key = self.create_quality_profile(language)
        if profile_key:
            self.change_parent_quality_profile(language, profile_key)
            self.deactivate_all_rules(profile_key)
            self.activate_security_rules(profile_key)
            self.set_default_profile(language, profile_key)
            print(f"DevSecOps.bot quality profile created and configured for {language}.")
            if language in EXCLUDE_LANGUAGES:
                self.deactivate_all_rules(profile_key)

    def set_default_profile(self, language, profile_key):
        endpoint = f"{self.base_url}/api/qualityprofiles/set_default"
        data = {
            "language": language,
            "qualityProfile": f"{language}-{PROFILE_SUFFIX}",
        }
        self._request_post(endpoint, data)

    @staticmethod
    def run(language):
        sonarqube_api = SonarQubeAPI()
        sonarqube_api.setup_quality_profile(language)


if __name__ == "__main__":
    BASE_URL = "http://localhost:9000"
    SQ_USERNAME = "admin"
    SQ_PASSWORD = "admin"
    EXCLUDE_LANGUAGES = []

    parser = argparse.ArgumentParser(description="Script to setup quality profiles in SonarQube.")
    parser.add_argument("--base_url", default=BASE_URL, help="Base URL of the SonarQube instance.")
    parser.add_argument("--username", default=SQ_USERNAME, help="Username for authentication.")
    parser.add_argument("--password", default=SQ_PASSWORD, help="Password for authentication.")
    args = parser.parse_args()

    # Update global variables based on command-line arguments
    BASE_URL = args.base_url
    SQ_USERNAME = args.username
    SQ_PASSWORD = args.password

    if args.base_url:
        BASE_URL = args.base_url
    if args.username:
        SQ_USERNAME = args.username
    if args.password:
        SQ_PASSWORD = args.password

    LANGUAGES = ['azureresourcemanager', 'cloudformation', 'cs', 'css', 'docker', 'flex', 'go', 'java', 'js',
                 'json',
                 'jsp', 'kotlin', 'kubernetes', 'php', 'py', 'ruby', 'scala', 'secrets', 'terraform', 'text', 'ts',
                 'vbnet', 'web', 'xml', 'yaml']
    pool = ThreadPool(4)
    pool.map(SonarQubeAPI.run, LANGUAGES)
    pool.close()
    pool.join()



