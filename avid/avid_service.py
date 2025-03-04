import os
import json
import logging
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AVIDService:
    """
    Service for interacting with the AI Vulnerability Database (AVID).
    """
    
    def __init__(self, api_key: str = None, api_url: str = None):
        """
        Initialize the AVID service.
        
        Args:
            api_key: API key for accessing AVID. If None, will try to load from environment.
            api_url: URL for the AVID API. If None, will use the default URL.
        """
        self.api_key = api_key or os.environ.get("AVID_API_KEY")
        self.api_url = api_url or "https://api.avidatabase.com/v1"  # Example URL
        
        if not self.api_key:
            logger.warning("No AVID API key provided. Some functionality may be limited.")
    
    def get_vulnerabilities(self, query: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities from AVID based on the query.
        
        Args:
            query: Query parameters for filtering vulnerabilities.
            
        Returns:
            List of vulnerability records.
        """
        endpoint = f"{self.api_url}/vulnerabilities"
        
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            response = requests.get(endpoint, params=query, headers=headers)
            response.raise_for_status()
            
            vulnerabilities = response.json().get("vulnerabilities", [])
            logger.info(f"Retrieved {len(vulnerabilities)} vulnerabilities from AVID")
            return vulnerabilities
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve vulnerabilities from AVID: {e}")
            # For demo purposes, return mock data if API call fails
            return self._get_mock_vulnerabilities()
    
    def _get_mock_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Get mock vulnerability data for demonstration purposes.
        
        Returns:
            List of mock vulnerability records.
        """
        return [
            {
                "id": "AVID-2023-001",
                "title": "Prompt Injection Vulnerability",
                "description": "Vulnerability where malicious input can manipulate the AI model's behavior.",
                "severity": "high",
                "affected_systems": ["LLM-based applications"],
                "mitigation": "Implement input validation and sanitization.",
                "published_date": "2023-01-15"
            },
            {
                "id": "AVID-2023-002",
                "title": "Data Leakage in Model Responses",
                "description": "Vulnerability where the model may leak sensitive information in its responses.",
                "severity": "critical",
                "affected_systems": ["Generative AI models"],
                "mitigation": "Implement output filtering and sensitive data detection.",
                "published_date": "2023-02-20"
            },
            {
                "id": "AVID-2023-003",
                "title": "Model Poisoning Attack",
                "description": "Vulnerability where the model training data is poisoned to introduce backdoors.",
                "severity": "medium",
                "affected_systems": ["AI models trained on public data"],
                "mitigation": "Implement robust data validation during training.",
                "published_date": "2023-03-10"
            }
        ]
    
    def check_prompt_vulnerabilities(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Check a prompt for potential vulnerabilities.
        
        Args:
            prompt: The prompt to check.
            
        Returns:
            List of detected vulnerabilities.
        """
        endpoint = f"{self.api_url}/check/prompt"
        
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            data = {"prompt": prompt}
            response = requests.post(endpoint, json=data, headers=headers)
            response.raise_for_status()
            
            vulnerabilities = response.json().get("vulnerabilities", [])
            logger.info(f"Detected {len(vulnerabilities)} vulnerabilities in prompt")
            return vulnerabilities
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to check prompt vulnerabilities: {e}")
            # For demo purposes, return mock data if API call fails
            return self._check_mock_prompt_vulnerabilities(prompt)
    
    def _check_mock_prompt_vulnerabilities(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Check a prompt for potential vulnerabilities using mock data.
        
        Args:
            prompt: The prompt to check.
            
        Returns:
            List of detected vulnerabilities.
        """
        vulnerabilities = []
        
        # Check for potential prompt injection
        if "ignore previous instructions" in prompt.lower() or "system prompt" in prompt.lower():
            vulnerabilities.append({
                "id": "AVID-2023-001",
                "title": "Prompt Injection Attempt",
                "description": "Potential attempt to manipulate the AI model's behavior.",
                "severity": "high",
                "confidence": 0.85,
                "matched_text": prompt
            })
        
        # Check for potential data extraction attempts
        if "dump" in prompt.lower() or "extract all" in prompt.lower() or "list all" in prompt.lower():
            vulnerabilities.append({
                "id": "AVID-2023-002",
                "title": "Data Extraction Attempt",
                "description": "Potential attempt to extract sensitive information.",
                "severity": "medium",
                "confidence": 0.75,
                "matched_text": prompt
            })
        
        return vulnerabilities
    
    def report_vulnerability(self, vulnerability_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Report a new vulnerability to AVID.
        
        Args:
            vulnerability_data: Data about the vulnerability.
            
        Returns:
            Response from the AVID API.
        """
        endpoint = f"{self.api_url}/vulnerabilities/report"
        
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            response = requests.post(endpoint, json=vulnerability_data, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            logger.info(f"Reported vulnerability to AVID: {result.get('id')}")
            return result
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to report vulnerability to AVID: {e}")
            # For demo purposes, return mock response if API call fails
            return {
                "id": f"AVID-MOCK-{datetime.now().strftime('%Y%m%d%H%M%S')}",
                "status": "received",
                "message": "Vulnerability report received (mock response)"
            }
    
    def get_vulnerability_by_id(self, vulnerability_id: str) -> Optional[Dict[str, Any]]:
        """
        Get a specific vulnerability by ID.
        
        Args:
            vulnerability_id: ID of the vulnerability to retrieve.
            
        Returns:
            Vulnerability record if found, None otherwise.
        """
        endpoint = f"{self.api_url}/vulnerabilities/{vulnerability_id}"
        
        try:
            headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            
            vulnerability = response.json()
            logger.info(f"Retrieved vulnerability {vulnerability_id} from AVID")
            return vulnerability
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve vulnerability {vulnerability_id} from AVID: {e}")
            # For demo purposes, return mock data if API call fails
            mock_vulnerabilities = self._get_mock_vulnerabilities()
            for vuln in mock_vulnerabilities:
                if vuln["id"] == vulnerability_id:
                    return vuln
            return None 