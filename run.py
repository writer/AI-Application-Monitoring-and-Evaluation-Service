#!/usr/bin/env python3
"""
Run script for AI Application Monitoring and Evaluation Service.
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Add the project directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import the Flask app
from projects.main import app

if __name__ == "__main__":
    # Get port from environment or use default
    port = int(os.environ.get("PORT", 8000))
    
    # Get debug mode from environment or use default
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    
    print(f"Starting AI Monitoring Service on port {port}...")
    print(f"Debug mode: {'enabled' if debug else 'disabled'}")
    print("Press Ctrl+C to stop the server")
    
    # Run the app
    app.run(host="0.0.0.0", port=port, debug=debug) 