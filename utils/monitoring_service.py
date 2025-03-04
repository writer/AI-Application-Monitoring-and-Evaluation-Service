import logging
import uuid
import datetime
import json
import yaml
from typing import Dict, List, Any, Optional

from projects.models.monitoring import (
    db, AIRequest, SensitiveDataDetection, VulnerabilityDetection, 
    AIResponse, MonitoringMetrics, AIApplication, CustomGuardrailRule
)
from projects.guardrails.guardrails_service import GuardrailsService
from projects.avid.avid_service import AVIDService
from projects.utils.policy_manager import PolicyManager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MonitoringService:
    """
    Service for monitoring AI applications.
    """
    
    def __init__(self, db_instance=None, guardrails_service=None, avid_service=None, policy_manager=None):
        """
        Initialize the MonitoringService.
        
        Args:
            db_instance: SQLAlchemy database instance.
            guardrails_service: GuardrailsService instance.
            avid_service: AVIDService instance.
            policy_manager: PolicyManager instance.
        """
        self.db = db_instance or db
        self.guardrails = guardrails_service or GuardrailsService()
        self.avid = avid_service or AVIDService()
        self.policy_manager = policy_manager or PolicyManager()
        self.app_guardrails_instances = {}  # Cache for app-specific guardrails instances
    
    def process_ai_request(self, prompt: str, user_id: Optional[str] = None, 
                          policy_name: str = "default", app_id: Optional[str] = None,
                          org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Process an AI request by detecting sensitive data and vulnerabilities.
        
        Args:
            prompt: The prompt to process.
            user_id: Optional user ID.
            policy_name: Name of the policy to apply.
            app_id: Optional application ID.
            org_id: Optional organization ID.
            
        Returns:
            Dictionary containing processed request data.
        """
        # Generate a unique request ID
        request_id = str(uuid.uuid4())
        
        # Get policy rules
        policy_rules = self.policy_manager.get_policy_rules(policy_name)
        if not policy_rules:
            logger.warning(f"Policy {policy_name} not found. Using default policy.")
            policy_name = "default"
            policy_rules = self.policy_manager.get_policy_rules(policy_name)
        
        # Get application-specific guardrails if app_id is provided
        guardrails_service = self.guardrails
        custom_patterns = None
        
        if app_id:
            # Get the application
            query = AIApplication.query.filter_by(app_id=app_id)
            if org_id:
                query = query.filter_by(org_id=org_id)
            application = query.first()
            
            if application:
                # Use application's default policy if not specified
                if policy_name == "default" and application.default_policy != "default":
                    policy_name = application.default_policy
                    policy_rules = self.policy_manager.get_policy_rules(policy_name)
                
                # Use application-specific guardrails if available
                if application.guardrails_config:
                    guardrails_service = self._get_app_guardrails_instance(app_id, application.guardrails_config, org_id)
                
                # Get custom rules for this application
                custom_rules = CustomGuardrailRule.query.filter_by(customer_id=application.customer_id).all()
                if custom_rules:
                    custom_patterns = []
                    for rule in custom_rules:
                        if rule.rule_type == "regex" and rule.pattern:
                            custom_patterns.append({
                                "type": "regex",
                                "pattern": rule.pattern,
                                "data_type": rule.data_type,
                                "description": rule.description or rule.name,
                                "default_action": rule.default_action
                            })
                
                # Use the org_id from the application if not provided
                if not org_id:
                    org_id = application.org_id
        
        # Process the prompt with guardrails
        guardrails_result = guardrails_service.process_input(prompt, policy_rules, custom_patterns)
        
        # Check for vulnerabilities
        vulnerabilities = self.avid.check_prompt_vulnerabilities(prompt)
        
        # Create AI request record
        ai_request = AIRequest(
            request_id=request_id,
            user_id=user_id,
            original_prompt=prompt,
            masked_prompt=guardrails_result["masked_text"],
            session_id=guardrails_result["session_id"],
            policy_applied=policy_name,
            app_id=app_id,
            org_id=org_id
        )
        
        # Add to database
        self.db.session.add(ai_request)
        self.db.session.flush()  # Flush to get the ID
        
        # Create sensitive data detection records
        for item in guardrails_result["detected_items"]:
            detection = SensitiveDataDetection(
                request_id=ai_request.id,
                data_type=item["type"],
                description=item["description"],
                action_taken=item.get("action", "mask"),
                confidence=item.get("confidence", 0.9)
            )
            self.db.session.add(detection)
        
        # Create vulnerability detection records
        for vuln in vulnerabilities:
            vulnerability = VulnerabilityDetection(
                request_id=ai_request.id,
                vulnerability_id=vuln["id"],
                title=vuln["title"],
                description=vuln["description"],
                severity=vuln["severity"],
                confidence=vuln.get("confidence", 0.8)
            )
            self.db.session.add(vulnerability)
        
        # Commit to database
        self.db.session.commit()
        
        # Record metrics
        self._record_metrics(
            "ai_request_processed",
            1.0,
            {
                "user_id": user_id,
                "policy": policy_name,
                "app_id": app_id,
                "sensitive_data_count": len(guardrails_result["detected_items"]),
                "vulnerability_count": len(vulnerabilities)
            }
        )
        
        # Return processed request data
        return {
            "request_id": request_id,
            "masked_prompt": guardrails_result["masked_text"],
            "session_id": guardrails_result["session_id"],
            "sensitive_data_detected": len(guardrails_result["detected_items"]) > 0,
            "vulnerabilities_detected": len(vulnerabilities) > 0,
            "can_proceed": self._can_proceed(guardrails_result["detected_items"], vulnerabilities, policy_rules)
        }
    
    def process_ai_response(self, request_id: str, masked_response: str, 
                           token_usage: Optional[Dict[str, int]] = None) -> Dict[str, Any]:
        """
        Process an AI response by rehydrating masked data.
        
        Args:
            request_id: The request ID.
            masked_response: The masked response from the AI.
            token_usage: Optional token usage information.
            
        Returns:
            Dictionary containing processed response data.
        """
        # Find the request
        ai_request = AIRequest.query.filter_by(request_id=request_id).first()
        if not ai_request:
            logger.error(f"Request {request_id} not found")
            return {"error": "Request not found"}
        
        # Get the appropriate guardrails service
        guardrails_service = self.guardrails
        if ai_request.app_id:
            application = AIApplication.query.filter_by(app_id=ai_request.app_id).first()
            if application and application.guardrails_config:
                guardrails_service = self._get_app_guardrails_instance(ai_request.app_id, application.guardrails_config, ai_request.org_id)
        
        # Rehydrate the response
        rehydrated_response = guardrails_service.process_output(masked_response, ai_request.session_id)
        
        # Create AI response record
        ai_response = AIResponse(
            request_id=ai_request.id,
            masked_response=masked_response,
            rehydrated_response=rehydrated_response
        )
        
        # Add token usage if provided
        if token_usage:
            ai_response.completion_tokens = token_usage.get("completion_tokens")
            ai_response.prompt_tokens = token_usage.get("prompt_tokens")
            ai_response.total_tokens = token_usage.get("total_tokens")
        
        # Add to database
        self.db.session.add(ai_response)
        self.db.session.commit()
        
        # Record metrics
        self._record_metrics(
            "ai_response_processed",
            1.0,
            {
                "user_id": ai_request.user_id,
                "policy": ai_request.policy_applied,
                "app_id": ai_request.app_id,
                "completion_tokens": ai_response.completion_tokens,
                "prompt_tokens": ai_response.prompt_tokens,
                "total_tokens": ai_response.total_tokens
            }
        )
        
        # Return processed response data
        return {
            "request_id": request_id,
            "rehydrated_response": rehydrated_response,
            "token_usage": token_usage
        }
    
    def get_request_history(self, user_id: Optional[str] = None, app_id: Optional[str] = None,
                           limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        """
        Get request history.
        
        Args:
            user_id: Optional user ID to filter by.
            app_id: Optional application ID to filter by.
            limit: Maximum number of records to return.
            offset: Offset for pagination.
            
        Returns:
            List of request records.
        """
        query = AIRequest.query
        
        if user_id:
            query = query.filter_by(user_id=user_id)
        
        if app_id:
            query = query.filter_by(app_id=app_id)
        
        query = query.order_by(AIRequest.timestamp.desc()).limit(limit).offset(offset)
        
        return [request.to_dict() for request in query.all()]
    
    def get_request_details(self, request_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a request.
        
        Args:
            request_id: The request ID.
            
        Returns:
            Dictionary containing request details.
        """
        ai_request = AIRequest.query.filter_by(request_id=request_id).first()
        if not ai_request:
            logger.error(f"Request {request_id} not found")
            return {"error": "Request not found"}
        
        result = ai_request.to_dict()
        
        # Add detections
        result["detections"] = [detection.to_dict() for detection in ai_request.detections]
        
        # Add vulnerabilities
        result["vulnerabilities"] = [vuln.to_dict() for vuln in ai_request.vulnerabilities]
        
        # Add response if available
        if ai_request.response:
            result["response"] = ai_request.response.to_dict()
        
        return result
    
    def get_metrics(self, metric_name: Optional[str] = None, 
                   start_time: Optional[datetime.datetime] = None,
                   end_time: Optional[datetime.datetime] = None,
                   dimensions: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Get monitoring metrics.
        
        Args:
            metric_name: Optional metric name to filter by.
            start_time: Optional start time for filtering.
            end_time: Optional end time for filtering.
            dimensions: Optional dimensions to filter by.
            
        Returns:
            List of metric records.
        """
        query = MonitoringMetrics.query
        
        if metric_name:
            query = query.filter_by(metric_name=metric_name)
        
        if start_time:
            query = query.filter(MonitoringMetrics.timestamp >= start_time)
        
        if end_time:
            query = query.filter(MonitoringMetrics.timestamp <= end_time)
        
        # Filter by dimensions if provided
        if dimensions:
            for key, value in dimensions.items():
                query = query.filter(MonitoringMetrics.dimensions[key].astext == str(value))
        
        query = query.order_by(MonitoringMetrics.timestamp.desc())
        
        return [metric.to_dict() for metric in query.all()]
    
    def _record_metrics(self, metric_name: str, metric_value: float, 
                       dimensions: Optional[Dict[str, Any]] = None) -> None:
        """
        Record a metric.
        
        Args:
            metric_name: Name of the metric.
            metric_value: Value of the metric.
            dimensions: Optional dimensions for the metric.
        """
        metric = MonitoringMetrics(
            metric_name=metric_name,
            metric_value=metric_value,
            dimensions=dimensions
        )
        
        self.db.session.add(metric)
        self.db.session.commit()
    
    def _can_proceed(self, detected_items: List[Dict[str, Any]], 
                    vulnerabilities: List[Dict[str, Any]],
                    policy_rules: Dict[str, Any]) -> bool:
        """
        Determine if the request can proceed based on detected items and policy.
        
        Args:
            detected_items: List of detected sensitive data items.
            vulnerabilities: List of detected vulnerabilities.
            policy_rules: Policy rules to apply.
            
        Returns:
            True if the request can proceed, False otherwise.
        """
        # Check if any detected items have a "block" action
        for item in detected_items:
            data_type = item["type"]
            if data_type in policy_rules and policy_rules[data_type]["action"] == "block":
                return False
        
        # Check if any high-severity vulnerabilities are detected
        for vuln in vulnerabilities:
            if vuln["severity"] == "high" or vuln["severity"] == "critical":
                return False
        
        return True
    
    def _get_app_guardrails_instance(self, app_id: str, config: Dict[str, Any], org_id: Optional[str] = None) -> GuardrailsService:
        """
        Get or create a guardrails instance for an application.
        
        Args:
            app_id: Application ID.
            config: Guardrails configuration.
            org_id: Optional organization ID.
            
        Returns:
            GuardrailsService instance.
        """
        # Create a cache key that includes both app_id and org_id if provided
        cache_key = f"{app_id}_{org_id}" if org_id else app_id
        
        if cache_key in self.app_guardrails_instances:
            return self.app_guardrails_instances[cache_key]
        
        # Create a new instance
        instance = GuardrailsService(custom_config=config)
        self.app_guardrails_instances[cache_key] = instance
        return instance
    
    def create_application(self, name: str, customer_id: str, description: Optional[str] = None,
                          guardrails_config: Optional[Dict[str, Any]] = None,
                          default_policy: str = "default", app_id: Optional[str] = None,
                          org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Create a new AI application.
        
        Args:
            name: Application name.
            customer_id: Customer ID.
            description: Optional application description.
            guardrails_config: Optional guardrails configuration.
            default_policy: Default policy to apply.
            app_id: Optional user-provided application ID.
            org_id: Optional organization ID.
            
        Returns:
            Dictionary containing the created application.
        """
        # Validate guardrails config if provided
        if guardrails_config and not self.guardrails.validate_config(guardrails_config):
            return {"error": "Invalid guardrails configuration"}
        
        # Validate policy if not default
        if default_policy != "default" and not self.policy_manager.get_policy(default_policy):
            return {"error": f"Policy {default_policy} not found"}
        
        # Generate a unique app ID if not provided
        if not app_id:
            app_id = str(uuid.uuid4())
        
        # Use customer_id as org_id if not provided
        if not org_id:
            org_id = customer_id
        
        # Check if an application with the same app_id and org_id already exists
        existing_app = AIApplication.query.filter_by(app_id=app_id, org_id=org_id).first()
        if existing_app:
            return {"error": f"Application with app_id {app_id} and org_id {org_id} already exists"}
        
        # Create the application
        application = AIApplication(
            app_id=app_id,
            org_id=org_id,
            name=name,
            description=description,
            customer_id=customer_id,
            guardrails_config=guardrails_config,
            default_policy=default_policy
        )
        
        # Add to database
        self.db.session.add(application)
        self.db.session.commit()
        
        logger.info(f"Created application {name} with ID {app_id} for organization {org_id}")
        return application.to_dict()
    
    def update_application(self, app_id: str, name: Optional[str] = None,
                          description: Optional[str] = None,
                          guardrails_config: Optional[Dict[str, Any]] = None,
                          default_policy: Optional[str] = None,
                          active: Optional[bool] = None) -> Dict[str, Any]:
        """
        Update an AI application.
        
        Args:
            app_id: Application ID.
            name: Optional new name.
            description: Optional new description.
            guardrails_config: Optional new guardrails configuration.
            default_policy: Optional new default policy.
            active: Optional new active status.
            
        Returns:
            Dictionary containing the updated application.
        """
        # Find the application
        application = AIApplication.query.filter_by(app_id=app_id).first()
        if not application:
            logger.error(f"Application {app_id} not found")
            return {"error": "Application not found"}
        
        # Validate guardrails config if provided
        if guardrails_config is not None and not self.guardrails.validate_config(guardrails_config):
            return {"error": "Invalid guardrails configuration"}
        
        # Validate policy if provided and not default
        if default_policy is not None and default_policy != "default" and not self.policy_manager.get_policy(default_policy):
            return {"error": f"Policy {default_policy} not found"}
        
        # Update fields
        if name is not None:
            application.name = name
        
        if description is not None:
            application.description = description
        
        if guardrails_config is not None:
            application.guardrails_config = guardrails_config
            # Remove cached instance if it exists
            if app_id in self.app_guardrails_instances:
                del self.app_guardrails_instances[app_id]
        
        if default_policy is not None:
            application.default_policy = default_policy
        
        if active is not None:
            application.active = active
        
        # Update timestamp
        application.updated_at = datetime.datetime.utcnow()
        
        # Save to database
        self.db.session.commit()
        
        logger.info(f"Updated application {app_id}")
        return application.to_dict()
    
    def get_application(self, app_id: str, org_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Get an AI application.
        
        Args:
            app_id: Application ID.
            org_id: Optional organization ID.
            
        Returns:
            Dictionary containing the application.
        """
        query = AIApplication.query.filter_by(app_id=app_id)
        if org_id:
            query = query.filter_by(org_id=org_id)
        application = query.first()
        
        if not application:
            logger.error(f"Application {app_id} not found")
            return {"error": "Application not found"}
        
        return application.to_dict()
    
    def list_applications(self, customer_id: Optional[str] = None,
                         active_only: bool = True) -> List[Dict[str, Any]]:
        """
        List AI applications.
        
        Args:
            customer_id: Optional customer ID to filter by.
            active_only: Whether to return only active applications.
            
        Returns:
            List of application dictionaries.
        """
        query = AIApplication.query
        
        if customer_id:
            query = query.filter_by(customer_id=customer_id)
        
        if active_only:
            query = query.filter_by(active=True)
        
        return [app.to_dict() for app in query.all()]
    
    def create_custom_rule(self, name: str, customer_id: str, rule_type: str,
                          data_type: str, pattern: Optional[str] = None,
                          prompt_template: Optional[str] = None,
                          description: Optional[str] = None,
                          default_action: str = "mask") -> Dict[str, Any]:
        """
        Create a custom guardrail rule.
        
        Args:
            name: Rule name.
            customer_id: Customer ID.
            rule_type: Rule type (regex, semantic, llm).
            data_type: Data type (pii, phi, pci, ip, custom).
            pattern: Optional regex pattern.
            prompt_template: Optional LLM prompt template.
            description: Optional rule description.
            default_action: Default action (mask, block, log).
            
        Returns:
            Dictionary containing the created rule.
        """
        # Validate rule type
        valid_rule_types = ["regex", "semantic", "llm"]
        if rule_type not in valid_rule_types:
            return {"error": f"Invalid rule type. Must be one of: {', '.join(valid_rule_types)}"}
        
        # Validate data type
        valid_data_types = ["pii", "phi", "pci", "ip", "custom"]
        if data_type not in valid_data_types:
            return {"error": f"Invalid data type. Must be one of: {', '.join(valid_data_types)}"}
        
        # Validate action
        valid_actions = ["mask", "block", "log"]
        if default_action not in valid_actions:
            return {"error": f"Invalid action. Must be one of: {', '.join(valid_actions)}"}
        
        # Validate pattern for regex rules
        if rule_type == "regex" and not pattern:
            return {"error": "Pattern is required for regex rules"}
        
        # Validate prompt template for LLM rules
        if rule_type == "llm" and not prompt_template:
            return {"error": "Prompt template is required for LLM rules"}
        
        # Generate a unique rule ID
        rule_id = str(uuid.uuid4())
        
        # Create the rule
        rule = CustomGuardrailRule(
            rule_id=rule_id,
            name=name,
            description=description,
            customer_id=customer_id,
            rule_type=rule_type,
            pattern=pattern,
            prompt_template=prompt_template,
            data_type=data_type,
            default_action=default_action
        )
        
        # Add to database
        self.db.session.add(rule)
        self.db.session.commit()
        
        logger.info(f"Created custom rule {name} with ID {rule_id}")
        return rule.to_dict()
    
    def get_custom_rule(self, rule_id: str) -> Dict[str, Any]:
        """
        Get a custom guardrail rule.
        
        Args:
            rule_id: Rule ID.
            
        Returns:
            Dictionary containing the rule.
        """
        rule = CustomGuardrailRule.query.filter_by(rule_id=rule_id).first()
        if not rule:
            logger.error(f"Rule {rule_id} not found")
            return {"error": "Rule not found"}
        
        return rule.to_dict()
    
    def list_custom_rules(self, customer_id: Optional[str] = None,
                         rule_type: Optional[str] = None,
                         data_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List custom guardrail rules.
        
        Args:
            customer_id: Optional customer ID to filter by.
            rule_type: Optional rule type to filter by.
            data_type: Optional data type to filter by.
            
        Returns:
            List of rule dictionaries.
        """
        query = CustomGuardrailRule.query
        
        if customer_id:
            query = query.filter_by(customer_id=customer_id)
        
        if rule_type:
            query = query.filter_by(rule_type=rule_type)
        
        if data_type:
            query = query.filter_by(data_type=data_type)
        
        return [rule.to_dict() for rule in query.all()]
    
    def create_guardrails_config_from_text(self, config_text: str, config_format: str = "yaml") -> Dict[str, Any]:
        """
        Create a guardrails configuration from text.
        
        Args:
            config_text: Configuration text.
            config_format: Format of the configuration text (yaml or json).
            
        Returns:
            Configuration dictionary.
        """
        try:
            config = self.guardrails.create_config_from_text(config_text, config_format)
            
            # Validate the configuration
            if not self.guardrails.validate_config(config):
                return {"error": "Invalid configuration"}
            
            return config
        except Exception as e:
            logger.error(f"Failed to create configuration from text: {e}")
            return {"error": str(e)}
            
    def create_guardrails_config_from_natural_language(self, natural_language_text: str) -> Dict[str, Any]:
        """
        Create a guardrails configuration from natural language description.
        
        Args:
            natural_language_text: Natural language description of the guardrails.
            
        Returns:
            Configuration dictionary.
        """
        try:
            config = self.guardrails.create_config_from_natural_language(natural_language_text)
            
            # Validate the configuration
            if not self.guardrails.validate_config(config):
                return {"error": "Invalid configuration generated from natural language"}
            
            return config
        except Exception as e:
            logger.error(f"Failed to create configuration from natural language: {e}")
            return {"error": str(e)} 