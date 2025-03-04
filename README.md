# AI Application Monitoring and Evaluation Service

A comprehensive backend service for monitoring and evaluating AI applications using NeMo Guardrails and AI Vulnerability Database (AVID).

## Features

### Sensitive Data Protection

- **Detect**: Identify PHI, PII, PCI, intellectual property, and other sensitive data in prompts in real-time
- **Treat**: Apply policies to detected data according to granular controls you set prior to submission
- **Rehydrate**: Review outputs upon return, with protected terms rehydrated back to their submission state

### AI Vulnerability Detection

- Integration with AVID to detect potential vulnerabilities in AI prompts
- Protection against prompt injection, data leakage, and other AI-specific vulnerabilities
- Configurable severity levels and actions

### Policy Management

- Create and manage data protection policies
- Apply different policies based on use case or data sensitivity
- Default policies for common scenarios (default, strict, permissive)

### Comprehensive Monitoring

- Track all AI requests and responses
- Record metrics for analysis and compliance
- Detailed logging of detected sensitive data and vulnerabilities

### Custom AI Applications

- Register and manage multiple AI applications with different guardrails configurations
- Define application-specific guardrails and policies
- Track metrics and requests per application

### Dynamic Guardrails Configuration

- Create guardrails configurations from YAML or JSON text
- Validate guardrails configurations before applying them
- Apply different guardrails to different applications

### Custom Guardrail Rules

- Create custom regex patterns for detecting sensitive data
- Define custom data types and actions
- Apply custom rules to specific applications

## Architecture

The service is built with a modular architecture:

- **GuardrailsService**: Handles sensitive data detection, masking, and rehydration
- **AVIDService**: Integrates with the AI Vulnerability Database
- **PolicyManager**: Manages data protection policies
- **MonitoringService**: Coordinates the overall monitoring process

## API Endpoints

### AI Processing

- `POST /api/ai/process`: Process an AI request with guardrails and AVID checks
- `POST /api/ai/response`: Process an AI response by rehydrating masked data

### Monitoring

- `GET /api/ai/requests`: Get AI request history
- `GET /api/ai/requests/<request_id>`: Get detailed information about an AI request
- `GET /api/ai/metrics`: Get AI monitoring metrics

### Policy Management

- `GET /api/policies`: Get available policies
- `GET /api/policies/<policy_name>`: Get a specific policy
- `POST /api/policies`: Create a new policy
- `PUT /api/policies/<policy_name>`: Update an existing policy
- `DELETE /api/policies/<policy_name>`: Delete a policy

### AI Application Management

- `POST /api/applications`: Create a new AI application with custom guardrails
- `GET /api/applications/<app_id>`: Get an AI application
- `GET /api/applications`: List AI applications
- `PUT /api/applications/<app_id>`: Update an AI application

### Custom Guardrail Rules

- `POST /api/rules`: Create a custom guardrail rule
- `GET /api/rules/<rule_id>`: Get a custom guardrail rule
- `GET /api/rules`: List custom guardrail rules

### Guardrails Configuration

- `POST /api/guardrails/validate`: Validate a guardrails configuration
- `POST /api/guardrails/from-text`: Create a guardrails configuration from text

## Getting Started

### Prerequisites

- Python 3.8+
- Flask
- SQLAlchemy
- NeMo Guardrails
- PostgreSQL

### Installation

1. Clone the repository
2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```
3. Set up environment variables:
   ```
   DATABASE_URI=postgresql://postgres:postgres@localhost:5432/ai_monitoring
   AVID_API_KEY=your_api_key
   WRITER_API_KEY=your_writer_api_key
   ```
4. Set up PostgreSQL database:
   ```
   createdb ai_monitoring
   ```
5. Initialize the database:
   ```
   python projects/init_db.py
   ```

### Running the Service

```
python projects/run.py
```

The service will be available at http://localhost:8000

## Usage Examples

### Processing an AI Request

```python
import requests
import json

# Process an AI request
response = requests.post(
    "http://localhost:8000/api/ai/process",
    json={
        "prompt": "My social security number is 123-45-6789 and my credit card is 4111-1111-1111-1111",
        "user_id": "user123",
        "policy": "default",
        "app_id": "app123"  # Optional application ID
    }
)

result = response.json()
print(f"Request ID: {result['request_id']}")
print(f"Masked prompt: {result['masked_prompt']}")
print(f"Session ID: {result['session_id']}")
print(f"Sensitive data detected: {result['sensitive_data_detected']}")
print(f"Vulnerabilities detected: {result['vulnerabilities_detected']}")
print(f"Can proceed: {result['can_proceed']}")

# If the request can proceed, send it to your AI model and get a response
if result['can_proceed']:
    # This would be your call to an AI model
    ai_response = "Here is your masked data: [PII_12345678]"
    
    # Process the AI response
    response = requests.post(
        "http://localhost:8000/api/ai/response",
        json={
            "request_id": result['request_id'],
            "masked_response": ai_response,
            "token_usage": {
                "prompt_tokens": 20,
                "completion_tokens": 10,
                "total_tokens": 30
            }
        }
    )
    
    rehydrated_result = response.json()
    print(f"Rehydrated response: {rehydrated_result['rehydrated_response']}")
```

### Creating a Custom Policy

```python
import requests
import json

# Create a custom policy
response = requests.post(
    "http://localhost:8000/api/policies",
    json={
        "name": "custom_policy",
        "description": "Custom policy for handling sensitive data",
        "rules": {
            "pii": {
                "action": "mask",
                "reason": "PII should be masked"
            },
            "phi": {
                "action": "block",
                "reason": "PHI is not allowed"
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
)

print(response.json())
```

### Creating an AI Application with Custom Guardrails

```python
import requests
import json

# Create a custom guardrails configuration
guardrails_config = {
    "models": [
        {
            "type": "main",
            "engine": "local",
            "model": "gpt-3.5-turbo"
        }
    ],
    "rails": {
        "input": {
            "flows": [
                "detect_sensitive_data",
                "check_avid_vulnerabilities"
            ]
        },
        "output": {
            "flows": [
                "check_output_for_sensitive_data"
            ]
        }
    },
    "sensitive_data_types": [
        {
            "name": "pii",
            "description": "Personally Identifiable Information",
            "patterns": [
                {
                    "type": "regex",
                    "pattern": "\\b\\d{3}-\\d{2}-\\d{4}\\b",
                    "description": "Social Security Number"
                },
                {
                    "type": "regex",
                    "pattern": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b",
                    "description": "Email Address"
                }
            ]
        }
    ]
}

# Create an AI application
response = requests.post(
    "http://localhost:8000/api/applications",
    json={
        "name": "My AI App",
        "customer_id": "customer123",
        "description": "My custom AI application with guardrails",
        "guardrails_config": guardrails_config,
        "default_policy": "strict"
    }
)

app = response.json()
print(f"Application ID: {app['app_id']}")
print(f"Application Name: {app['name']}")
```

### Creating a Custom Guardrail Rule

```python
import requests
import json

# Create a custom guardrail rule
response = requests.post(
    "http://localhost:8000/api/rules",
    json={
        "name": "Custom Credit Card Rule",
        "customer_id": "customer123",
        "rule_type": "regex",
        "data_type": "pci",
        "pattern": "\\b(?:\\d[ -]*?){13,16}\\b",
        "description": "Custom credit card number pattern",
        "default_action": "mask"
    }
)

rule = response.json()
print(f"Rule ID: {rule['rule_id']}")
print(f"Rule Name: {rule['name']}")
```

### Creating Guardrails Configuration from Text

```python
import requests
import json

# Create guardrails configuration from YAML text
config_text = """
models:
  - type: main
    engine: local
    model: gpt-3.5-turbo

rails:
  input:
    flows:
      - detect_sensitive_data
  output:
    flows:
      - check_output_for_sensitive_data

sensitive_data_types:
  - name: custom_pii
    description: "Custom PII"
    patterns:
      - type: regex
        pattern: '\\b\\d{10}\\b'
        description: "10-digit ID number"
"""

response = requests.post(
    "http://localhost:8000/api/guardrails/from-text",
    json={
        "config_text": config_text,
        "config_format": "yaml"
    }
)

result = response.json()
print(f"Valid configuration: {result['valid']}")
print(f"Configuration: {result['config']}")
```

### Creating Guardrails Configuration from Natural Language

```python
import requests
import json

# Create guardrails configuration from natural language description
description = """
I need a guardrail that protects healthcare data. It should detect patient IDs, 
medical record numbers, and any PHI. It should also detect credit card numbers. 
The guardrail should mask all sensitive data and block any prompts that contain 
too much PHI. It should use the GPT-4 model.
"""

response = requests.post(
    "http://localhost:8000/api/guardrails/from-natural-language",
    json={
        "description": description
    }
)

result = response.json()
print(f"Valid configuration: {result['valid']}")
print(f"Configuration: {result['config']}")
```

## License

This project is licensed under the MIT License - see the LICENSE file for details. 