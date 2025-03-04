import os
import json
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PolicyManager:
    """
    Utility for managing data protection policies.
    """
    
    def __init__(self, policy_file: str = None):
        """
        Initialize the PolicyManager with the specified policy file.
        
        Args:
            policy_file: Path to the policy file. If None, will use a default path.
        """
        if policy_file is None:
            policy_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                      "config", "data_policies.json")
        
        self.policy_file = policy_file
        self.policies = self._load_policies()
    
    def _load_policies(self) -> Dict[str, Any]:
        """
        Load policies from the policy file.
        
        Returns:
            Dictionary containing the policies.
        """
        try:
            if os.path.exists(self.policy_file):
                with open(self.policy_file, 'r') as f:
                    policies = json.load(f)
                logger.info(f"Loaded policies from {self.policy_file}")
                return policies
            else:
                logger.warning(f"Policy file {self.policy_file} not found. Using default policies.")
                return self._get_default_policies()
        except Exception as e:
            logger.error(f"Failed to load policies: {e}")
            return self._get_default_policies()
    
    def _get_default_policies(self) -> Dict[str, Any]:
        """
        Get default policies.
        
        Returns:
            Dictionary containing default policies.
        """
        return {
            "default": {
                "name": "Default Policy",
                "description": "Default policy for handling sensitive data",
                "rules": {
                    "pii": {
                        "action": "mask",
                        "reason": "PII must be protected by default"
                    },
                    "phi": {
                        "action": "mask",
                        "reason": "PHI must be protected by default"
                    },
                    "pci": {
                        "action": "mask",
                        "reason": "PCI must be protected by default"
                    },
                    "ip": {
                        "action": "mask",
                        "reason": "IP must be protected by default"
                    }
                }
            },
            "strict": {
                "name": "Strict Policy",
                "description": "Strict policy for handling sensitive data",
                "rules": {
                    "pii": {
                        "action": "block",
                        "reason": "PII is not allowed under strict policy"
                    },
                    "phi": {
                        "action": "block",
                        "reason": "PHI is not allowed under strict policy"
                    },
                    "pci": {
                        "action": "block",
                        "reason": "PCI is not allowed under strict policy"
                    },
                    "ip": {
                        "action": "block",
                        "reason": "IP is not allowed under strict policy"
                    }
                }
            },
            "permissive": {
                "name": "Permissive Policy",
                "description": "Permissive policy for handling sensitive data",
                "rules": {
                    "pii": {
                        "action": "mask",
                        "reason": "PII should be masked"
                    },
                    "phi": {
                        "action": "mask",
                        "reason": "PHI should be masked"
                    },
                    "pci": {
                        "action": "mask",
                        "reason": "PCI should be masked"
                    },
                    "ip": {
                        "action": "log",
                        "reason": "IP should be logged but allowed"
                    }
                }
            }
        }
    
    def save_policies(self) -> bool:
        """
        Save policies to the policy file.
        
        Returns:
            True if successful, False otherwise.
        """
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.policy_file), exist_ok=True)
            
            with open(self.policy_file, 'w') as f:
                json.dump(self.policies, f, indent=2)
            
            logger.info(f"Saved policies to {self.policy_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to save policies: {e}")
            return False
    
    def get_policy(self, policy_name: str) -> Optional[Dict[str, Any]]:
        """
        Get a policy by name.
        
        Args:
            policy_name: Name of the policy to retrieve.
            
        Returns:
            Policy dictionary if found, None otherwise.
        """
        return self.policies.get(policy_name)
    
    def get_policy_rules(self, policy_name: str) -> Optional[Dict[str, Any]]:
        """
        Get the rules for a policy.
        
        Args:
            policy_name: Name of the policy to retrieve rules for.
            
        Returns:
            Rules dictionary if found, None otherwise.
        """
        policy = self.get_policy(policy_name)
        if policy:
            return policy.get("rules")
        return None
    
    def create_policy(self, policy_name: str, policy_data: Dict[str, Any]) -> bool:
        """
        Create a new policy.
        
        Args:
            policy_name: Name of the policy to create.
            policy_data: Policy data.
            
        Returns:
            True if successful, False otherwise.
        """
        if policy_name in self.policies:
            logger.warning(f"Policy {policy_name} already exists. Use update_policy to update it.")
            return False
        
        self.policies[policy_name] = policy_data
        logger.info(f"Created policy {policy_name}")
        return self.save_policies()
    
    def update_policy(self, policy_name: str, policy_data: Dict[str, Any]) -> bool:
        """
        Update an existing policy.
        
        Args:
            policy_name: Name of the policy to update.
            policy_data: Updated policy data.
            
        Returns:
            True if successful, False otherwise.
        """
        if policy_name not in self.policies:
            logger.warning(f"Policy {policy_name} does not exist. Use create_policy to create it.")
            return False
        
        self.policies[policy_name] = policy_data
        logger.info(f"Updated policy {policy_name}")
        return self.save_policies()
    
    def delete_policy(self, policy_name: str) -> bool:
        """
        Delete a policy.
        
        Args:
            policy_name: Name of the policy to delete.
            
        Returns:
            True if successful, False otherwise.
        """
        if policy_name not in self.policies:
            logger.warning(f"Policy {policy_name} does not exist.")
            return False
        
        del self.policies[policy_name]
        logger.info(f"Deleted policy {policy_name}")
        return self.save_policies()
    
    def list_policies(self) -> List[Dict[str, Any]]:
        """
        List all policies.
        
        Returns:
            List of policy dictionaries.
        """
        return [{"name": name, **policy} for name, policy in self.policies.items()] 