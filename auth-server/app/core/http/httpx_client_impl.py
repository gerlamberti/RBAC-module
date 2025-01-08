from typing import Optional, Dict, Any

import httpx

from core.http.rest_client import RestClient

class HttpxClientImpl(RestClient):

    def __init__(self, base_url: str, verbose: bool):
        if validate_base_url(base_url):
            self.base_url = base_url
        self.base_client = httpx.Client(base_url=base_url, )

    def get(self, resource: str, params: Optional[Dict[str, Any]] = None) -> Any:
        httpx.get(f"${self.base_url}resource")

    def post(self, resource: str, json: Optional[Dict[str, Any]] = None) -> Any:
        httpx.post(f"${self.base_url}resource")
        pass

def validate_base_url(base_url) -> bool:
    if not base_url:
        raise ValueError("Base URL not provided.")
    if not base_url.startswith("http"):
        raise ValueError("Base URL must start with http(s)://")
    if not base_url.endswith("/"):
        raise ValueError("Base URL must end with a slash.")
    return True