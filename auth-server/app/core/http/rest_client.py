from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, Union

# Define the generic HTTP client interface
class RestClient(ABC):
    @abstractmethod
    def get(self, resource: str, params: Optional[Dict[str, Any]] = None) -> Any:
        pass

    @abstractmethod
    def post(self, resource: str, json: Optional[Dict[str, Any]] = None) -> Any:
        pass
