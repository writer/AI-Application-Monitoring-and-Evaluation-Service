#!/usr/bin/env python3
"""
Example script demonstrating natural language to guardrails configuration.
"""

import requests
import json
import sys
import os
import yaml
from pprint import pprint

# Base URL for the API
BASE_URL = "http://localhost:8000"

def create_guardrails_from_natural_language(description):
    """Create a guardrails configuration from natural language description."""
    print("\n=== Creating Guardrails Configuration from Natural Language ===\n")
    print(f"Description: {description}")
    
    # Create guardrails configuration from natural language
    response = requests.post(
        f"{BASE_URL}/api/guardrails/from-natural-language",
        json={"description": description}
    )
    
    if response.status_code != 200:
        print(f"Error: {response.json().get('error', 'Unknown error')}")
        return None
    
    result = response.json()
    print("\nGuardrails configuration created successfully!")
    print("\nConfiguration:")
    print(yaml.dump(result["config"], default_flow_style=False))
    
    return result["config"]

def create_application_with_nl_config(config, name, customer_id):
    """Create an application with the generated configuration."""
    print("\n=== Creating Application with Generated Configuration ===\n")
    
    response = requests.post(
        f"{BASE_URL}/api/applications",
        json={
            "name": name,
            "customer_id": customer_id,
            "description": "Application created with natural language configuration",
            "guardrails_config": config,
            "default_policy": "strict"
        }
    )
    
    if response.status_code != 201:
        print(f"Error: {response.json().get('error', 'Unknown error')}")
        return None
    
    app = response.json()
    print(f"Application created successfully with ID: {app['app_id']}")
    return app

def test_application(app_id):
    """Test the application with a prompt containing sensitive data."""
    print("\n=== Testing Application ===\n")
    
    # Create a prompt with sensitive data
    prompt = """
    Patient John Doe (MRN12345678) with ID 1234567890 was diagnosed with hypertension.
    His credit card number is 4111-1111-1111-1111 and his address is 123 Main St, Anytown, USA.
    His date of birth is 01/01/1980 and his treatment includes lisinopril 10mg daily.
    """
    
    print(f"Prompt: {prompt}")
    
    # Process the prompt
    response = requests.post(
        f"{BASE_URL}/api/ai/process",
        json={
            "prompt": prompt,
            "user_id": "test_user",
            "policy": "strict",
            "app_id": app_id
        }
    )
    
    if response.status_code != 200:
        print(f"Error: {response.json().get('error', 'Unknown error')}")
        return None
    
    result = response.json()
    print("\nPrompt processed successfully!")
    print(f"Request ID: {result['request_id']}")
    print(f"Masked prompt: {result['masked_prompt']}")
    print(f"Session ID: {result['session_id']}")
    print(f"Can proceed: {result['can_proceed']}")
    
    print("\nSensitive data detected:")
    for item in result['sensitive_data_detected']:
        print(f"  - Type: {item['data_type']}, Description: {item['description']}, Action: {item['action']}")
    
    return result

def main():
    """Run the example."""
    print("Starting Natural Language Guardrails Example...")
    
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
    
    # Example 1: Healthcare data protection
    description1 = """
    I need a guardrail that protects healthcare data. It should detect patient IDs 
    which are 10-digit numbers, medical record numbers which start with MRN followed by 
    8 digits, and any PHI including names, addresses, and dates of birth. 
    
    It should also detect credit card numbers and mask them. The guardrail should 
    mask all sensitive data by default, but block any prompts that contain more than 
    3 instances of PHI. It should use the GPT-4 model for processing.
    
    For healthcare data, it should specifically look for terms like "diagnosis", 
    "treatment", "medication", and "procedure" followed by specific medical information.
    """
    
    config1 = create_guardrails_from_natural_language(description1)
    if config1:
        app1 = create_application_with_nl_config(config1, "Healthcare App", "customer123")
        if app1:
            test_application(app1['app_id'])
    
    # Example 2: Financial data protection
    description2 = """
    Create a guardrail for financial data protection. It should detect credit card numbers,
    bank account numbers (which are 10-12 digits), and routing numbers (9 digits).
    
    It should also detect financial terms like "balance", "account", "transfer", and "payment"
    when they are followed by dollar amounts. The guardrail should mask all financial data
    and block any prompts that try to perform financial transactions.
    
    Use the GPT-3.5-turbo model for processing.
    """
    
    config2 = create_guardrails_from_natural_language(description2)
    if config2:
        app2 = create_application_with_nl_config(config2, "Financial App", "customer456")
        if app2:
            test_application(app2['app_id'])
    
    print("\nExample completed successfully!")

if __name__ == "__main__":
    main() 