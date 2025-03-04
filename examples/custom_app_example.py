#!/usr/bin/env python3
"""
Example script demonstrating custom AI applications and guardrails.
"""

import requests
import json
import sys
import os
import yaml
from pprint import pprint

# Base URL for the API
BASE_URL = "http://localhost:8000"

def create_guardrails_from_natural_language():
    """Create a guardrails configuration from natural language description."""
    print("\n=== Creating Guardrails Configuration from Natural Language ===\n")
    
    # Natural language description of the guardrails
    description = """
    I need a guardrail that protects healthcare data. It should detect patient IDs 
    which are 10-digit numbers, medical record numbers which start with MRN followed by 
    8 digits, and any PHI including names, addresses, and dates of birth. 
    
    It should also detect credit card numbers and mask them. The guardrail should 
    mask all sensitive data by default, but block any prompts that contain more than 
    3 instances of PHI. It should use the Palmyra-x-004 model for processing.
    
    For healthcare data, it should specifically look for terms like "diagnosis", 
    "treatment", "medication", and "procedure" followed by specific medical information.
    """
    
    # Create guardrails configuration from natural language
    response = requests.post(
        f"{BASE_URL}/api/guardrails/from-natural-language",
        json={"description": description}
    )
    
    if response.status_code != 200:
        print(f"Error: {response.json().get('error', 'Unknown error')}")
        return None
    
    result = response.json()
    print("Guardrails configuration created successfully!")
    print("\nConfiguration:")
    print(yaml.dump(result["config"], default_flow_style=False))
    
    return result["config"]

def create_custom_application():
    """Create a custom AI application with guardrails."""
    print("\n=== Creating Custom AI Application ===\n")
    
    # Load guardrails configuration from YAML
    guardrails_config = {
        "models": [
            {
                "type": "main",
                "engine": "local",
                "model": "palmyra-x-004"
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
            },
            {
                "name": "healthcare",
                "description": "Healthcare Information",
                "patterns": [
                    {
                        "type": "regex",
                        "pattern": "\\b(patient|diagnosis|treatment|medication|prescription|symptom|disease)\\b",
                        "description": "Healthcare terms"
                    }
                ]
            }
        ]
    }
    
    # Create the application
    response = requests.post(
        f"{BASE_URL}/api/applications",
        json={
            "name": "Healthcare AI Assistant",
            "customer_id": "healthcare_provider_123",
            "description": "AI assistant for healthcare providers with enhanced PHI protection",
            "guardrails_config": guardrails_config,
            "default_policy": "strict"
        }
    )
    
    if response.status_code != 201:
        print(f"Error creating application: {response.status_code}")
        print(response.text)
        return None
    
    app = response.json()
    print("Application created successfully:")
    print(f"  Application ID: {app['app_id']}")
    print(f"  Name: {app['name']}")
    print(f"  Description: {app['description']}")
    print(f"  Default Policy: {app['default_policy']}")
    
    return app

def create_custom_rule(customer_id):
    """Create a custom guardrail rule."""
    print("\n=== Creating Custom Guardrail Rule ===\n")
    
    # Create a custom rule for medical record numbers
    response = requests.post(
        f"{BASE_URL}/api/rules",
        json={
            "name": "Medical Record Number",
            "customer_id": customer_id,
            "rule_type": "regex",
            "data_type": "phi",
            "pattern": "\\b(MRN|Medical Record Number|Record Number)\\s*[:#]?\\s*\\d{6,10}\\b",
            "description": "Medical Record Number pattern",
            "default_action": "mask"
        }
    )
    
    if response.status_code != 201:
        print(f"Error creating rule: {response.status_code}")
        print(response.text)
        return None
    
    rule = response.json()
    print("Rule created successfully:")
    print(f"  Rule ID: {rule['rule_id']}")
    print(f"  Name: {rule['name']}")
    print(f"  Pattern: {rule['pattern']}")
    print(f"  Data Type: {rule['data_type']}")
    print(f"  Default Action: {rule['default_action']}")
    
    return rule

def test_custom_application(app_id):
    """Test the custom AI application."""
    print("\n=== Testing Custom AI Application ===\n")
    
    # Example prompt with sensitive healthcare data
    prompt = """
    Patient: John Smith
    Date of Birth: 01/15/1980
    Medical Record Number: 12345678
    Email: john.smith@example.com
    
    Patient presents with symptoms of hypertension and elevated blood glucose levels.
    Current medications include Lisinopril 10mg daily and Metformin 500mg twice daily.
    
    Please analyze this patient's condition and recommend treatment options.
    """
    
    # Process the request
    response = requests.post(
        f"{BASE_URL}/api/ai/process",
        json={
            "prompt": prompt,
            "user_id": "doctor_jane",
            "policy": "default",  # Will use the application's default policy
            "app_id": app_id
        }
    )
    
    if response.status_code != 200:
        print(f"Error processing request: {response.status_code}")
        print(response.text)
        return None
    
    result = response.json()
    print("Request processed successfully:")
    print(f"  Request ID: {result['request_id']}")
    print(f"  Sensitive data detected: {result['sensitive_data_detected']}")
    print(f"  Vulnerabilities detected: {result['vulnerabilities_detected']}")
    print(f"  Can proceed: {result['can_proceed']}")
    
    print("\nMasked prompt:")
    print(result['masked_prompt'])
    
    # If the request can proceed, simulate an AI response
    if result.get('can_proceed', False):
        # Simulate an AI model response with masked data
        ai_response = f"""
        Based on the information provided for the patient with Medical Record Number {result['masked_prompt'].split('Medical Record Number:')[1].split()[0]}, 
        I recommend the following:
        
        1. Continue current medications: Lisinopril 10mg daily and Metformin 500mg twice daily
        2. Monitor blood pressure and blood glucose levels regularly
        3. Schedule follow-up appointment in 3 months
        4. Consider adding a statin if LDL cholesterol is elevated
        5. Recommend lifestyle modifications including:
           - Low sodium diet
           - Regular exercise (30 minutes daily)
           - Weight management
        
        Please contact the patient at {result['masked_prompt'].split('Email:')[1].split()[0]} to discuss these recommendations.
        """
        
        # Process the response
        response = requests.post(
            f"{BASE_URL}/api/ai/response",
            json={
                "request_id": result['request_id'],
                "masked_response": ai_response,
                "token_usage": {
                    "prompt_tokens": 150,
                    "completion_tokens": 120,
                    "total_tokens": 270
                }
            }
        )
        
        if response.status_code != 200:
            print(f"Error processing response: {response.status_code}")
            print(response.text)
            return None
        
        rehydrated_result = response.json()
        print("\nRehydrated response:")
        print(rehydrated_result['rehydrated_response'])
    
    return result

def get_request_details(request_id):
    """Get detailed information about a request."""
    print("\n=== Getting Request Details ===\n")
    
    response = requests.get(f"{BASE_URL}/api/ai/requests/{request_id}")
    
    if response.status_code != 200:
        print(f"Error getting request details: {response.status_code}")
        print(response.text)
        return None
    
    result = response.json()
    print("Request details retrieved successfully:")
    print(f"  Request ID: {result['request_id']}")
    print(f"  Timestamp: {result['timestamp']}")
    print(f"  User ID: {result['user_id']}")
    print(f"  Policy applied: {result['policy_applied']}")
    print(f"  Application ID: {result['app_id']}")
    
    print(f"\nDetected sensitive data items: {len(result['detections'])}")
    for i, detection in enumerate(result['detections'], 1):
        print(f"  {i}. Type: {detection['data_type']}, Description: {detection['description']}, Action: {detection['action_taken']}")
    
    return result

def main():
    """Run the example."""
    print("Starting Custom AI Application Example...")
    
    # Check if the server is running
    try:
        response = requests.get(f"{BASE_URL}/api/policies")
        if response.status_code != 200:
            print(f"Error connecting to server: {response.status_code}")
            print("Make sure the server is running at http://localhost:8000")
            return
    except requests.exceptions.ConnectionError:
        print("Error connecting to server")
        print("Make sure the server is running at http://localhost:8000")
        return
    
    # Create guardrails configuration from natural language
    nl_config = create_guardrails_from_natural_language()
    if not nl_config:
        print("Skipping natural language guardrails configuration example")
    
    # Create a custom application
    app = create_custom_application()
    if not app:
        return
    
    # Create a custom rule
    rule = create_custom_rule(app['customer_id'])
    if not rule:
        return
    
    # Test the custom application
    result = test_custom_application(app['app_id'])
    if not result:
        return
    
    # Get request details
    get_request_details(result['request_id'])
    
    print("\nExample completed successfully!")

if __name__ == "__main__":
    main() 