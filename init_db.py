#!/usr/bin/env python3
"""
Initialization script for AI Application Monitoring and Evaluation Service.
"""

import os
import sys
import json
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask
from projects.models.monitoring import db
from projects.utils.policy_manager import PolicyManager

def init_db():
    """Initialize the database and create default policies."""
    print("Initializing database...")
    
    # Create a Flask app
    app = Flask(__name__)
    
    # Configure SQLAlchemy
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'postgresql://postgres:postgres@localhost:5432/ai_monitoring')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Initialize database
    db.init_app(app)
    
    # Create database tables
    with app.app_context():
        db.create_all()
        print("Database tables created successfully.")
    
    # Initialize policy manager and save default policies
    policy_manager = PolicyManager()
    policy_manager.save_policies()
    print("Default policies created successfully.")
    
    # Print available policies
    policies = policy_manager.list_policies()
    print(f"\nAvailable policies ({len(policies)}):")
    for i, policy in enumerate(policies, 1):
        print(f"  {i}. {policy['name']}: {policy['description']}")
        rules = policy.get('rules', {})
        for data_type, rule in rules.items():
            print(f"     - {data_type}: {rule['action']} ({rule['reason']})")
    
    print("\nInitialization completed successfully!")

if __name__ == "__main__":
    init_db() 