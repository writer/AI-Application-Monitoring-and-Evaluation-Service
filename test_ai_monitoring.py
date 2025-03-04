#!/usr/bin/env python3
"""
Test script for AI Application Monitoring and Evaluation Service.
"""

import requests
import json
import sys
import time
from pprint import pprint

BASE_URL = "http://localhost:8000"

def test_process_ai_request():
    """Test processing an AI request with sensitive data."""
    print("\n=== Testing AI Request Processing ===\n")
    
    # Example prompt with sensitive data
    prompt = """
    Patient Name: John Smith
    Date of Birth: 01/15/1980
    SSN: 123-45-6789
    Medical Record Number: 1234567890
    Diagnosis: Hypertension, Type 2 Diabetes
    Medications: Lisinopril 10mg daily, Metformin 500mg twice daily
    Credit Card: 4111-1111-1111-1111
    Expiration Date: 12/25
    CVV: 123
    
    Please analyze this patient's condition and recommend treatment options.
    """
    
    # Process the request
    response = requests.post(
        f"{BASE_URL}/api/ai/process",
        json={
            "prompt": prompt,
            "user_id": "test_user",
            "policy": "default"
        }
    )
    
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
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
    
    return result

def test_process_ai_response(request_result):
    """Test processing an AI response with masked data."""
    if not request_result:
        print("Skipping response processing test (no request result)")
        return
    
    print("\n=== Testing AI Response Processing ===\n")
    
    # Simulate an AI model response with masked data
    masked_response = f"""
    Based on the patient information provided:
    
    The patient {request_result['masked_prompt'].split()[2]} has been diagnosed with Hypertension and Type 2 Diabetes.
    Current medications include Lisinopril 10mg daily and Metformin 500mg twice daily.
    
    Recommendations:
    1. Continue current medications
    2. Monitor blood pressure and blood glucose regularly
    3. Follow a low-sodium, low-carbohydrate diet
    4. Exercise for at least 30 minutes daily
    5. Schedule follow-up appointment in 3 months
    
    Please note that the patient's SSN ({request_result['masked_prompt'].split('SSN:')[1].split()[0]}) has been recorded for billing purposes.
    """
    
    # Process the response
    response = requests.post(
        f"{BASE_URL}/api/ai/response",
        json={
            "request_id": request_result['request_id'],
            "masked_response": masked_response,
            "token_usage": {
                "prompt_tokens": 150,
                "completion_tokens": 120,
                "total_tokens": 270
            }
        }
    )
    
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return
    
    result = response.json()
    print("Response processed successfully:")
    print("\nRehydrated response:")
    print(result['rehydrated_response'])

def test_get_request_details(request_result):
    """Test retrieving request details."""
    if not request_result:
        print("Skipping request details test (no request result)")
        return
    
    print("\n=== Testing Request Details Retrieval ===\n")
    
    # Get request details
    response = requests.get(
        f"{BASE_URL}/api/ai/requests/{request_result['request_id']}"
    )
    
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return
    
    result = response.json()
    print("Request details retrieved successfully:")
    print(f"  Request ID: {result['request_id']}")
    print(f"  Timestamp: {result['timestamp']}")
    print(f"  User ID: {result['user_id']}")
    print(f"  Policy applied: {result['policy_applied']}")
    
    print(f"\nDetected sensitive data items: {len(result['detections'])}")
    for i, detection in enumerate(result['detections'], 1):
        print(f"  {i}. Type: {detection['data_type']}, Description: {detection['description']}, Action: {detection['action_taken']}")
    
    print(f"\nDetected vulnerabilities: {len(result['vulnerabilities'])}")
    for i, vuln in enumerate(result['vulnerabilities'], 1):
        print(f"  {i}. ID: {vuln['vulnerability_id']}, Title: {vuln['title']}, Severity: {vuln['severity']}")

def test_policies():
    """Test policy management."""
    print("\n=== Testing Policy Management ===\n")
    
    # Get available policies
    response = requests.get(f"{BASE_URL}/api/policies")
    
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return
    
    result = response.json()
    print(f"Available policies: {len(result['policies'])}")
    for i, policy in enumerate(result['policies'], 1):
        print(f"  {i}. {policy['name']}: {policy['description']}")
    
    # Create a custom policy
    custom_policy = {
        "name": "test_policy",
        "description": "Test policy for demonstration",
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
    
    response = requests.post(
        f"{BASE_URL}/api/policies",
        json=custom_policy
    )
    
    if response.status_code == 201:
        print("\nCustom policy created successfully:")
        print(f"  Name: {response.json()['name']}")
        print(f"  Description: {response.json()['description']}")
    elif response.status_code == 409:
        print("\nPolicy already exists, updating instead...")
        
        # Update the policy
        response = requests.put(
            f"{BASE_URL}/api/policies/test_policy",
            json={
                "description": "Updated test policy for demonstration",
                "rules": custom_policy["rules"]
            }
        )
        
        if response.status_code == 200:
            print("Policy updated successfully:")
            print(f"  Name: {response.json()['name']}")
            print(f"  Description: {response.json()['description']}")
        else:
            print(f"Error updating policy: {response.status_code}")
            print(response.text)
    else:
        print(f"Error creating policy: {response.status_code}")
        print(response.text)

def test_metrics():
    """Test metrics retrieval."""
    print("\n=== Testing Metrics Retrieval ===\n")
    
    # Get metrics
    response = requests.get(f"{BASE_URL}/api/ai/metrics")
    
    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        print(response.text)
        return
    
    result = response.json()
    print(f"Available metrics: {len(result['metrics'])}")
    for i, metric in enumerate(result['metrics'][:5], 1):  # Show only first 5 metrics
        print(f"  {i}. {metric['metric_name']}: {metric['metric_value']} ({metric['timestamp']})")
    
    if len(result['metrics']) > 5:
        print(f"  ... and {len(result['metrics']) - 5} more")

def main():
    """Run all tests."""
    print("Starting AI Monitoring Service tests...")
    
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
    
    # Run tests
    request_result = test_process_ai_request()
    test_process_ai_response(request_result)
    test_get_request_details(request_result)
    test_policies()
    test_metrics()
    
    print("\nAll tests completed!")

if __name__ == "__main__":
    main() 