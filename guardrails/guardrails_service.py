import os
import re
import json
import logging
import uuid
import yaml
from typing import Dict, List, Tuple, Any, Optional
from pathlib import Path
import writer

import nemoguardrails as ng
from nemoguardrails.rails.llm.config import RailsConfig

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GuardrailsService:
    """
    Service for detecting, masking, and rehydrating sensitive data using NeMo Guardrails.
    """
    
    def __init__(self, config_path: str = None, custom_config: Dict[str, Any] = None):
        """
        Initialize the GuardrailsService with the specified configuration.
        
        Args:
            config_path: Path to the guardrails configuration file.
            custom_config: Custom configuration dictionary.
        """
        if config_path is None and custom_config is None:
            config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                      "config", "guardrails_config.yml")
        
        self.config_path = config_path
        self.custom_config = custom_config
        self.config = self._load_config()
        self.guardrails = self._initialize_guardrails()
        self.sensitive_data_map = {}  # Maps masked tokens to original values
        
    def _load_config(self) -> RailsConfig:
        """Load the guardrails configuration."""
        try:
            if self.custom_config:
                # Create a temporary config file from the custom config
                temp_config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                              "config", f"temp_config_{uuid.uuid4().hex}.yml")
                
                with open(temp_config_path, 'w') as f:
                    yaml.dump(self.custom_config, f)
                
                config = RailsConfig.from_path(temp_config_path)
                
                # Clean up the temporary file
                os.remove(temp_config_path)
                
                logger.info("Loaded custom guardrails configuration")
                return config
            else:
                config = RailsConfig.from_path(self.config_path)
                logger.info(f"Loaded guardrails configuration from {self.config_path}")
                return config
        except Exception as e:
            logger.error(f"Failed to load guardrails configuration: {e}")
            raise
    
    def _initialize_guardrails(self) -> ng.LLMRails:
        """Initialize the NeMo Guardrails instance."""
        try:
            rails = ng.LLMRails(self.config)
            logger.info("Initialized NeMo Guardrails")
            return rails
        except Exception as e:
            logger.error(f"Failed to initialize NeMo Guardrails: {e}")
            raise
    
    def detect_sensitive_data(self, text: str, custom_patterns: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """
        Detect sensitive data in the input text.
        
        Args:
            text: The input text to analyze.
            custom_patterns: Optional list of custom patterns to check.
            
        Returns:
            A list of dictionaries containing information about detected sensitive data.
        """
        detected_items = []
        
        # Process standard patterns from config
        for data_type in self.config.sensitive_data_types:
            for pattern in data_type.patterns:
                if pattern.type == "regex":
                    matches = re.finditer(pattern.pattern, text)
                    for match in matches:
                        detected_items.append({
                            "type": data_type.name,
                            "description": pattern.description,
                            "value": match.group(),
                            "start": match.start(),
                            "end": match.end()
                        })
        
        # Process custom patterns if provided
        if custom_patterns:
            for pattern in custom_patterns:
                if pattern.get("type") == "regex" and pattern.get("pattern"):
                    try:
                        matches = re.finditer(pattern["pattern"], text)
                        for match in matches:
                            detected_items.append({
                                "type": pattern.get("data_type", "custom"),
                                "description": pattern.get("description", "Custom pattern"),
                                "value": match.group(),
                                "start": match.start(),
                                "end": match.end(),
                                "custom": True
                            })
                    except re.error as e:
                        logger.error(f"Invalid regex pattern: {pattern['pattern']} - {e}")
        
        logger.info(f"Detected {len(detected_items)} sensitive data items")
        return detected_items
    
    def mask_sensitive_data(self, text: str, custom_patterns: Optional[List[Dict[str, Any]]] = None) -> Tuple[str, str]:
        """
        Mask sensitive data in the input text.
        
        Args:
            text: The input text to mask.
            custom_patterns: Optional list of custom patterns to check.
            
        Returns:
            A tuple containing the masked text and a session ID for rehydration.
        """
        detected_items = self.detect_sensitive_data(text, custom_patterns)
        masked_text = text
        token_map = {}
        
        # Sort items by start position in reverse order to avoid index shifting
        detected_items.sort(key=lambda x: x["start"], reverse=True)
        
        for item in detected_items:
            # Generate a unique token for the sensitive data
            token = f"[{item['type'].upper()}_{uuid.uuid4().hex[:8]}]"
            
            # Replace the sensitive data with the token
            masked_text = masked_text[:item["start"]] + token + masked_text[item["end"]:]
            
            # Store the mapping for rehydration
            token_map[token] = item["value"]
        
        # Store the token map for later rehydration
        session_id = uuid.uuid4().hex
        self.sensitive_data_map[session_id] = token_map
        
        logger.info(f"Masked {len(token_map)} sensitive data items")
        return masked_text, session_id
    
    def rehydrate_data(self, masked_text: str, session_id: str) -> str:
        """
        Rehydrate masked data in the text.
        
        Args:
            masked_text: The masked text to rehydrate.
            session_id: The session ID for retrieving the token map.
            
        Returns:
            The rehydrated text.
        """
        if session_id not in self.sensitive_data_map:
            logger.warning(f"Session ID {session_id} not found in sensitive data map")
            return masked_text
        
        token_map = self.sensitive_data_map[session_id]
        rehydrated_text = masked_text
        
        for token, original_value in token_map.items():
            rehydrated_text = rehydrated_text.replace(token, original_value)
        
        logger.info(f"Rehydrated {len(token_map)} sensitive data items")
        return rehydrated_text
    
    def apply_policy(self, detected_items: List[Dict[str, Any]], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Apply a policy to detected sensitive data items.
        
        Args:
            detected_items: List of detected sensitive data items.
            policy: Policy to apply.
            
        Returns:
            List of items with policy applied.
        """
        for item in detected_items:
            data_type = item["type"]
            if data_type in policy:
                item["action"] = policy[data_type]["action"]
                item["reason"] = policy[data_type]["reason"]
            else:
                item["action"] = "mask"  # Default action
                item["reason"] = "Default policy"
        
        return detected_items
    
    def process_input(self, text: str, policy: Optional[Dict[str, Any]] = None, 
                     custom_patterns: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        """
        Process input text by detecting and masking sensitive data according to policy.
        
        Args:
            text: Input text to process.
            policy: Optional policy to apply.
            custom_patterns: Optional list of custom patterns to check.
            
        Returns:
            Dictionary containing processed text and metadata.
        """
        detected_items = self.detect_sensitive_data(text, custom_patterns)
        
        if policy:
            detected_items = self.apply_policy(detected_items, policy)
        
        masked_text, session_id = self.mask_sensitive_data(text, custom_patterns)
        
        return {
            "original_text": text,
            "masked_text": masked_text,
            "session_id": session_id,
            "detected_items": detected_items
        }
    
    def process_output(self, masked_output: str, session_id: str) -> str:
        """
        Process output text by rehydrating masked sensitive data.
        
        Args:
            masked_output: Masked output text.
            session_id: Session ID for retrieving token map.
            
        Returns:
            Rehydrated output text.
        """
        return self.rehydrate_data(masked_output, session_id)
    
    def create_config_from_text(self, config_text: str, config_format: str = "yaml") -> Dict[str, Any]:
        """
        Create a configuration dictionary from text.
        
        Args:
            config_text: Configuration text.
            config_format: Format of the configuration text (yaml or json).
            
        Returns:
            Configuration dictionary.
        """
        try:
            if config_format.lower() == "yaml":
                config = yaml.safe_load(config_text)
            elif config_format.lower() == "json":
                config = json.loads(config_text)
            else:
                raise ValueError(f"Unsupported config format: {config_format}")
            
            logger.info("Created configuration from text")
            return config
        except Exception as e:
            logger.error(f"Failed to create configuration from text: {e}")
            raise
    
    def create_config_from_natural_language(self, natural_language_text: str) -> Dict[str, Any]:
        """
        Create a guardrails configuration from natural language description.
        
        Args:
            natural_language_text: Natural language description of the guardrails.
            
        Returns:
            Configuration dictionary.
        """
        try:
            # Initialize Writer client
            client = writer.Writer(api_key=os.environ.get("WRITER_API_KEY"))
            
            # Create a prompt for the LLM
            prompt = f"""
            Convert the following natural language description into a NeMo Guardrails YAML configuration.
            The configuration should include models, rails, and sensitive data types as described.
            
            Natural language description:
            {natural_language_text}
            
            The output should be a valid YAML configuration with the following structure:
            ```yaml
            models:
              - type: main
                engine: local
                model: [model name]
            
            rails:
              input:
                flows:
                  - [input flow]
              output:
                flows:
                  - [output flow]
            
            sensitive_data_types:
              - name: [data type name]
                description: [description]
                patterns:
                  - type: regex
                    pattern: [regex pattern]
                    description: [pattern description]
            ```
            
            Only return the YAML configuration, nothing else.
            """
            
            # Call the Palmyra-x-004 LLM to generate the configuration
            response = client.completions.create(
                model="palmyra-x-004",
                prompt=prompt,
                temperature=0.1,
                max_tokens=2000,
                stop=["```"]
            )
            
            # Extract the YAML configuration from the response
            yaml_text = response.completion.strip()
            
            # Remove any markdown code block indicators
            yaml_text = re.sub(r'^```yaml\s*', '', yaml_text)
            yaml_text = re.sub(r'\s*```$', '', yaml_text)
            
            # Parse the YAML
            config = yaml.safe_load(yaml_text)
            
            # Validate the configuration
            if not self.validate_config(config):
                raise ValueError("Generated configuration is not valid")
            
            logger.info("Created configuration from natural language")
            return config
        except Exception as e:
            logger.error(f"Failed to create configuration from natural language: {e}")
            raise
    
    def create_guardrails_instance(self, config: Dict[str, Any]) -> GuardrailsService:
        """
        Create a new GuardrailsService instance with the specified configuration.
        
        Args:
            config: Configuration dictionary.
            
        Returns:
            New GuardrailsService instance.
        """
        return GuardrailsService(custom_config=config)
    
    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Validate a configuration dictionary.
        
        Args:
            config: Configuration dictionary to validate.
            
        Returns:
            True if valid, False otherwise.
        """
        try:
            # Check required sections
            required_sections = ["models", "rails", "sensitive_data_types"]
            for section in required_sections:
                if section not in config:
                    logger.error(f"Missing required section: {section}")
                    return False
            
            # Check sensitive_data_types
            for data_type in config.get("sensitive_data_types", []):
                if "name" not in data_type:
                    logger.error("Missing name in sensitive_data_type")
                    return False
                
                if "patterns" not in data_type:
                    logger.error(f"Missing patterns in sensitive_data_type: {data_type['name']}")
                    return False
                
                for pattern in data_type["patterns"]:
                    if "type" not in pattern or "pattern" not in pattern:
                        logger.error(f"Invalid pattern in sensitive_data_type: {data_type['name']}")
                        return False
            
            # Try to create a RailsConfig instance
            temp_config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                          "config", f"temp_config_{uuid.uuid4().hex}.yml")
            
            with open(temp_config_path, 'w') as f:
                yaml.dump(config, f)
            
            RailsConfig.from_path(temp_config_path)
            
            # Clean up the temporary file
            os.remove(temp_config_path)
            
            logger.info("Configuration is valid")
            return True
        except Exception as e:
            logger.error(f"Invalid configuration: {e}")
            return False 