from flask import Flask, request, jsonify
import logging
import os
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up logging for production-level tracing
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# PostgreSQL configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'postgresql://postgres:postgres@localhost:5432/ai_monitoring')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Import models and services
from projects.models.monitoring import db, AIRequest, SensitiveDataDetection, VulnerabilityDetection, AIResponse, MonitoringMetrics, AIApplication, CustomGuardrailRule
from projects.guardrails.guardrails_service import GuardrailsService
from projects.avid.avid_service import AVIDService
from projects.utils.policy_manager import PolicyManager
from projects.utils.monitoring_service import MonitoringService

# Initialize database
db.init_app(app)

# Initialize services
guardrails_service = GuardrailsService()
avid_service = AVIDService()
policy_manager = PolicyManager()
monitoring_service = MonitoringService(
    db_instance=db,
    guardrails_service=guardrails_service,
    avid_service=avid_service,
    policy_manager=policy_manager
)

# Define the Customer model for storing customer data.
class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)

    def to_dict(self):
        return {"id": self.id, "name": self.name, "email": self.email}

def process_medical_text(text):
    """
    Processes the input medical text.
    In a real-world system, this function would integrate with LLM Palmyra-med,
    Pass the text for analysis, and retrieve structured medical insights.
    """
    logging.info(f"Processing medical text: {text}")
    # Placeholder: Replace this with the actual API call to LLM Palmyra-med
    processed_text = f"Processed medical data for: {text}"
    return processed_text

# AI Monitoring Endpoints

@app.route('/api/ai/process', methods=['POST'])
def process_ai_request():
    """
    Process an AI request with guardrails and AVID checks.
    
    Expects a JSON payload with:
    - prompt: The prompt to process
    - user_id: (Optional) User ID
    - policy: (Optional) Policy name to apply
    - app_id: (Optional) Application ID
    - org_id: (Optional) Organization ID
    
    Returns a JSON response with the processed request data.
    """
    data = request.get_json()
    if not data or 'prompt' not in data:
        return jsonify({"error": "No prompt provided"}), 400
    
    prompt = data['prompt']
    user_id = data.get('user_id')
    policy = data.get('policy', 'default')
    app_id = data.get('app_id')
    org_id = data.get('org_id')
    
    result = monitoring_service.process_ai_request(prompt, user_id, policy, app_id, org_id)
    
    if not result.get('can_proceed', True):
        return jsonify({
            "error": "Request blocked due to policy violation or vulnerability",
            "request_id": result.get('request_id'),
            "sensitive_data_detected": result.get('sensitive_data_detected'),
            "vulnerabilities_detected": result.get('vulnerabilities_detected')
        }), 403
    
    return jsonify(result)

@app.route('/api/ai/response', methods=['POST'])
def process_ai_response():
    """
    Process an AI response by rehydrating masked data.
    
    Expects a JSON payload with:
    - request_id: The request ID
    - masked_response: The masked response from the AI
    - token_usage: (Optional) Token usage information
    
    Returns a JSON response with the processed response data.
    """
    data = request.get_json()
    if not data or 'request_id' not in data or 'masked_response' not in data:
        return jsonify({"error": "Request ID and masked response are required"}), 400
    
    request_id = data['request_id']
    masked_response = data['masked_response']
    token_usage = data.get('token_usage')
    
    result = monitoring_service.process_ai_response(request_id, masked_response, token_usage)
    
    if 'error' in result:
        return jsonify(result), 404
    
    return jsonify(result)

@app.route('/api/ai/requests', methods=['GET'])
def get_ai_requests():
    """
    Get AI request history.
    
    Query parameters:
    - user_id: (Optional) Filter by user ID
    - app_id: (Optional) Filter by application ID
    - limit: (Optional) Maximum number of records to return
    - offset: (Optional) Offset for pagination
    
    Returns a JSON response with the request history.
    """
    user_id = request.args.get('user_id')
    app_id = request.args.get('app_id')
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    result = monitoring_service.get_request_history(user_id, app_id, limit, offset)
    
    return jsonify({"requests": result, "count": len(result)})

@app.route('/api/ai/requests/<request_id>', methods=['GET'])
def get_ai_request_details(request_id):
    """
    Get detailed information about an AI request.
    
    Path parameters:
    - request_id: The request ID
    
    Returns a JSON response with the request details.
    """
    result = monitoring_service.get_request_details(request_id)
    
    if 'error' in result:
        return jsonify(result), 404
    
    return jsonify(result)

@app.route('/api/ai/metrics', methods=['GET'])
def get_ai_metrics():
    """
    Get AI monitoring metrics.
    
    Query parameters:
    - metric_name: (Optional) Filter by metric name
    - start_time: (Optional) Start time for filtering (ISO format)
    - end_time: (Optional) End time for filtering (ISO format)
    - dimensions: (Optional) JSON-encoded dimensions to filter by
    
    Returns a JSON response with the metrics.
    """
    import json
    from datetime import datetime
    
    metric_name = request.args.get('metric_name')
    
    start_time = request.args.get('start_time')
    if start_time:
        start_time = datetime.fromisoformat(start_time)
    
    end_time = request.args.get('end_time')
    if end_time:
        end_time = datetime.fromisoformat(end_time)
    
    dimensions = request.args.get('dimensions')
    if dimensions:
        dimensions = json.loads(dimensions)
    
    result = monitoring_service.get_metrics(metric_name, start_time, end_time, dimensions)
    
    return jsonify({"metrics": result, "count": len(result)})

# AI Application Management Endpoints

@app.route('/api/applications', methods=['POST'])
def create_application():
    """
    Create a new AI application with custom guardrails.
    
    Expects a JSON payload with:
    - name: Application name
    - customer_id: Customer ID
    - description: (Optional) Application description
    - guardrails_config: (Optional) Custom guardrails configuration
    - default_policy: (Optional) Default policy to apply
    - app_id: (Optional) User-provided application ID
    - org_id: (Optional) Organization ID
    
    Returns a JSON response with the created application.
    """
    data = request.get_json()
    if not data or 'name' not in data or 'customer_id' not in data:
        return jsonify({"error": "Name and customer_id are required"}), 400
    
    name = data['name']
    customer_id = data['customer_id']
    description = data.get('description')
    guardrails_config = data.get('guardrails_config')
    default_policy = data.get('default_policy', 'default')
    app_id = data.get('app_id')
    org_id = data.get('org_id')
    
    result = monitoring_service.create_application(
        name=name,
        customer_id=customer_id,
        description=description,
        guardrails_config=guardrails_config,
        default_policy=default_policy,
        app_id=app_id,
        org_id=org_id
    )
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result), 201

@app.route('/api/applications/<app_id>', methods=['GET'])
def get_application(app_id):
    """
    Get an AI application.
    
    Path parameters:
    - app_id: Application ID
    
    Query parameters:
    - org_id: (Optional) Organization ID
    
    Returns a JSON response with the application details.
    """
    org_id = request.args.get('org_id')
    result = monitoring_service.get_application(app_id, org_id)
    
    if 'error' in result:
        return jsonify(result), 404
    
    return jsonify(result)

@app.route('/api/applications', methods=['GET'])
def list_applications():
    """
    List AI applications.
    
    Query parameters:
    - customer_id: (Optional) Filter by customer ID
    - active_only: (Optional) Whether to return only active applications
    
    Returns a JSON response with the applications.
    """
    customer_id = request.args.get('customer_id')
    active_only = request.args.get('active_only', 'true').lower() == 'true'
    
    result = monitoring_service.list_applications(customer_id, active_only)
    
    return jsonify({"applications": result, "count": len(result)})

@app.route('/api/applications/<app_id>', methods=['PUT'])
def update_application(app_id):
    """
    Update an AI application.
    
    Path parameters:
    - app_id: Application ID
    
    Expects a JSON payload with:
    - name: (Optional) New application name
    - description: (Optional) New application description
    - guardrails_config: (Optional) New guardrails configuration
    - default_policy: (Optional) New default policy
    - active: (Optional) New active status
    
    Returns a JSON response with the updated application.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    result = monitoring_service.update_application(
        app_id=app_id,
        name=data.get('name'),
        description=data.get('description'),
        guardrails_config=data.get('guardrails_config'),
        default_policy=data.get('default_policy'),
        active=data.get('active')
    )
    
    if 'error' in result:
        return jsonify(result), 404 if result['error'] == 'Application not found' else 400
    
    return jsonify(result)

# Custom Guardrail Rules Endpoints

@app.route('/api/rules', methods=['POST'])
def create_custom_rule():
    """
    Create a custom guardrail rule.
    
    Expects a JSON payload with:
    - name: Rule name
    - customer_id: Customer ID
    - rule_type: Rule type (regex, semantic, llm)
    - data_type: Data type (pii, phi, pci, ip, custom)
    - pattern: (Optional) Regex pattern
    - prompt_template: (Optional) LLM prompt template
    - description: (Optional) Rule description
    - default_action: (Optional) Default action (mask, block, log)
    
    Returns a JSON response with the created rule.
    """
    data = request.get_json()
    if not data or 'name' not in data or 'customer_id' not in data or 'rule_type' not in data or 'data_type' not in data:
        return jsonify({"error": "Name, customer_id, rule_type, and data_type are required"}), 400
    
    result = monitoring_service.create_custom_rule(
        name=data['name'],
        customer_id=data['customer_id'],
        rule_type=data['rule_type'],
        data_type=data['data_type'],
        pattern=data.get('pattern'),
        prompt_template=data.get('prompt_template'),
        description=data.get('description'),
        default_action=data.get('default_action', 'mask')
    )
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify(result), 201

@app.route('/api/rules/<rule_id>', methods=['GET'])
def get_custom_rule(rule_id):
    """
    Get a custom guardrail rule.
    
    Path parameters:
    - rule_id: Rule ID
    
    Returns a JSON response with the rule details.
    """
    result = monitoring_service.get_custom_rule(rule_id)
    
    if 'error' in result:
        return jsonify(result), 404
    
    return jsonify(result)

@app.route('/api/rules', methods=['GET'])
def list_custom_rules():
    """
    List custom guardrail rules.
    
    Query parameters:
    - customer_id: (Optional) Filter by customer ID
    - rule_type: (Optional) Filter by rule type
    - data_type: (Optional) Filter by data type
    
    Returns a JSON response with the rules.
    """
    customer_id = request.args.get('customer_id')
    rule_type = request.args.get('rule_type')
    data_type = request.args.get('data_type')
    
    result = monitoring_service.list_custom_rules(customer_id, rule_type, data_type)
    
    return jsonify({"rules": result, "count": len(result)})

@app.route('/api/guardrails/validate', methods=['POST'])
def validate_guardrails_config():
    """
    Validate a guardrails configuration.
    
    Expects a JSON payload with:
    - config: Guardrails configuration
    
    Returns a JSON response with the validation result.
    """
    data = request.get_json()
    if not data or 'config' not in data:
        return jsonify({"error": "Configuration is required"}), 400
    
    is_valid = guardrails_service.validate_config(data['config'])
    
    return jsonify({"valid": is_valid})

@app.route('/api/guardrails/from-text', methods=['POST'])
def create_guardrails_from_text():
    """
    Create a guardrails configuration from text.
    
    Expects a JSON payload with:
    - config_text: Configuration text
    - config_format: (Optional) Format of the configuration text (yaml or json)
    
    Returns a JSON response with the created configuration.
    """
    data = request.get_json()
    if not data or 'config_text' not in data:
        return jsonify({"error": "Configuration text is required"}), 400
    
    config_text = data['config_text']
    config_format = data.get('config_format', 'yaml')
    
    result = monitoring_service.create_guardrails_config_from_text(config_text, config_format)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify({"config": result, "valid": True})

@app.route('/api/guardrails/from-natural-language', methods=['POST'])
def create_guardrails_from_natural_language():
    """
    Create a guardrails configuration from natural language description.
    
    Expects a JSON payload with:
    - description: Natural language description of the guardrails
    
    Returns a JSON response with the created configuration.
    """
    data = request.get_json()
    if not data or 'description' not in data:
        return jsonify({"error": "Natural language description is required"}), 400
    
    description = data['description']
    
    result = monitoring_service.create_guardrails_config_from_natural_language(description)
    
    if 'error' in result:
        return jsonify(result), 400
    
    return jsonify({"config": result, "valid": True})

# Policy Management Endpoints

@app.route('/api/policies', methods=['GET'])
def get_policies():
    """
    Get available policies.
    
    Returns a JSON response with the available policies.
    """
    policies = policy_manager.list_policies()
    
    return jsonify({"policies": policies, "count": len(policies)})

@app.route('/api/policies/<policy_name>', methods=['GET'])
def get_policy(policy_name):
    """
    Get a specific policy.
    
    Path parameters:
    - policy_name: The policy name
    
    Returns a JSON response with the policy details.
    """
    policy = policy_manager.get_policy(policy_name)
    
    if not policy:
        return jsonify({"error": f"Policy {policy_name} not found"}), 404
    
    return jsonify({"name": policy_name, **policy})

@app.route('/api/policies', methods=['POST'])
def create_policy():
    """
    Create a new policy.
    
    Expects a JSON payload with:
    - name: The policy name
    - description: Policy description
    - rules: Policy rules
    
    Returns a JSON response with the created policy.
    """
    data = request.get_json()
    if not data or 'name' not in data or 'rules' not in data:
        return jsonify({"error": "Policy name and rules are required"}), 400
    
    policy_name = data.pop('name')
    
    if policy_manager.get_policy(policy_name):
        return jsonify({"error": f"Policy {policy_name} already exists"}), 409
    
    success = policy_manager.create_policy(policy_name, data)
    
    if not success:
        return jsonify({"error": "Failed to create policy"}), 500
    
    return jsonify({"name": policy_name, **data}), 201

@app.route('/api/policies/<policy_name>', methods=['PUT'])
def update_policy(policy_name):
    """
    Update an existing policy.
    
    Path parameters:
    - policy_name: The policy name
    
    Expects a JSON payload with:
    - description: (Optional) Policy description
    - rules: (Optional) Policy rules
    
    Returns a JSON response with the updated policy.
    """
    data = request.get_json()
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    policy = policy_manager.get_policy(policy_name)
    if not policy:
        return jsonify({"error": f"Policy {policy_name} not found"}), 404
    
    # Update policy with new data
    updated_policy = {**policy, **data}
    
    success = policy_manager.update_policy(policy_name, updated_policy)
    
    if not success:
        return jsonify({"error": "Failed to update policy"}), 500
    
    return jsonify({"name": policy_name, **updated_policy})

@app.route('/api/policies/<policy_name>', methods=['DELETE'])
def delete_policy(policy_name):
    """
    Delete a policy.
    
    Path parameters:
    - policy_name: The policy name
    
    Returns a JSON response with the result.
    """
    policy = policy_manager.get_policy(policy_name)
    if not policy:
        return jsonify({"error": f"Policy {policy_name} not found"}), 404
    
    success = policy_manager.delete_policy(policy_name)
    
    if not success:
        return jsonify({"error": "Failed to delete policy"}), 500
    
    return jsonify({"message": f"Policy {policy_name} deleted successfully"})

# Original endpoints

@app.route('/api/process', methods=['POST'])
def process_endpoint():
    """
    Expects a JSON payload with a 'text' field.
    Returns a JSON response with the processed result from the LLM.
    """
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data['text']
    result = process_medical_text(text)
    return jsonify({"result": result})

# Endpoint to list all customers.
@app.route('/api/customers', methods=['GET'])
def get_customers():
    customers = Customer.query.all()
    return jsonify([customer.to_dict() for customer in customers])

# Endpoint to add a new customer.
@app.route('/api/customers', methods=['POST'])
def add_customer():
    """
    Expects a JSON payload with 'name' and 'email'.
    Adds a new customer and returns the created customer data.
    """
    data = request.get_json()
    if not data or 'name' not in data or 'email' not in data:
        return jsonify({"error": "Name and email are required"}), 400

    name = data['name']
    email = data['email']

    # Check if a customer with this email already exists.
    existing_customer = Customer.query.filter_by(email=email).first()
    if existing_customer:
        return jsonify({"error": "Customer with that email already exists"}), 400

    new_customer = Customer(name=name, email=email)
    db.session.add(new_customer)
    db.session.commit()

    return jsonify(new_customer.to_dict()), 201

# Endpoint to delete a customer by ID.
@app.route('/api/customers/<int:customer_id>', methods=['DELETE'])
def delete_customer(customer_id):
    """
    Deletes an existing customer by ID.
    Returns a confirmation message upon successful deletion.
    """
    customer = Customer.query.get(customer_id)
    if not customer:
        return jsonify({"error": "Customer not found"}), 404

    db.session.delete(customer)
    db.session.commit()
    return jsonify({"message": "Customer deleted successfully"}), 200

if __name__ == '__main__':
    # Create database tables if they don't already exist.
    with app.app_context():
        db.create_all()
    # For production deployments, consider using a production WSGI server
    # and environment-specific configuration.
    app.run(host='0.0.0.0', port=8000)
