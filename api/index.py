"""
Sentinel API - Backend Service for Content Auditing
====================================================
This Flask application acts as a security gateway that inspects incoming
requests and blocks potentially harmful or policy-violating content.

Author: Senior Backend Engineer
Purpose: Interview demonstration of API security patterns
"""

from flask import Flask, request, jsonify
import re

# Initialize Flask application
# Flask is a lightweight web framework for building REST APIs
app = Flask(__name__)
from flask_cors import CORS
CORS(app)

# ============================================================================
# CONFIGURATION: Banned Keywords
# ============================================================================
# These are patterns we want to block for security or business policy reasons
# In production, these would typically be stored in a database or config file
BANNED_KEYWORDS = [
    'DROP TABLE',           # SQL injection attempt
    'DELETE FROM',          # Destructive SQL command
    'refund > 500',         # Business rule: high-value refunds need manual review
    'angry',                # Sentiment filter: escalate negative customer interactions
    'unauthorized',         # Security keyword
    'exec(',                # Code injection attempt
    'eval(',                # Code injection attempt
    'wasting our time',     # Negative sentiment
    'shut up',              # Hostile language
    'idiot',                # Personal attack
]

# ============================================================================
# BUSINESS RULES
# ============================================================================
MAX_REFUND_AMOUNT = 500  # Maximum refund that can be auto-approved


def check_for_banned_keywords(data_str):
    """
    Scans the input string for any banned keywords (case-insensitive).
    
    Args:
        data_str (str): The stringified JSON data to scan
        
    Returns:
        tuple: (is_banned, keyword_found)
               - is_banned: Boolean indicating if banned content was found
               - keyword_found: The specific keyword that triggered the ban
    
    Interview talking points:
    - We convert to lowercase for case-insensitive matching
    - Could be optimized with Aho-Corasick algorithm for large keyword lists
    - In production, might use regex patterns for more sophisticated matching
    """
    data_lower = data_str.lower()
    
    # Iterate through each banned keyword
    for keyword in BANNED_KEYWORDS:
        if keyword.lower() in data_lower:
            return True, keyword
    
    return False, None


def check_refund_amount(data):
    """
    Checks if the request contains a refund amount exceeding business limits.
    
    Args:
        data (dict): The parsed JSON payload
        
    Returns:
        tuple: (is_blocked, amount)
               - is_blocked: Boolean indicating if refund exceeds limit
               - amount: The refund amount found (or None)
    
    Interview talking points:
    - This implements a business rule, not just security
    - We check multiple possible field names (refund_amount, refund, amount)
    - Error handling prevents crashes if fields don't exist
    - Could be extended to check transaction history, user tier, etc.
    """
    # Check various possible field names for refund amount
    # Real APIs often need to handle inconsistent field naming
    refund_fields = ['refund_amount', 'refund', 'amount']
    
    for field in refund_fields:
        if field in data:
            try:
                amount = float(data[field])
                if amount > MAX_REFUND_AMOUNT:
                    return True, amount
            except (ValueError, TypeError):
                # If we can't convert to float, skip this field
                # Prevents crashes on malformed data
                continue
    
    return False, None


# ============================================================================
# API ENDPOINT: /audit
# ============================================================================
# ============================================================================
# API ENDPOINT: /audit
# ============================================================================
@app.route('/api/audit', methods=['POST'])
def audit_request():
    """
    Main API endpoint that audits incoming requests for security/policy violations.
    
    HTTP Method: POST
    Content-Type: application/json
    
    Request body: Any valid JSON
    
    Response format:
        {
            "status": "APPROVED" | "BLOCKED",
            "reason": "explanation if blocked"
        }
    
    Interview talking points:
    - RESTful design: POST for actions that modify state
    - Input validation before processing
    - Specific error messages help with debugging but avoid leaking security details
    - HTTP status codes: 200 for success, 400 for bad input
    """
    
    # ========================================================================
    # STEP 1: Validate that request contains JSON
    # ========================================================================
    # get_json() parses the request body as JSON
    # It returns None if Content-Type isn't application/json or body is invalid
    try:
        data = request.get_json()
        if data is None:
            return jsonify({
                'status': 'BLOCKED',
                'reason': 'Invalid JSON payload or missing Content-Type header'
            }), 400
    except Exception as e:
        return jsonify({
            'status': 'BLOCKED',
            'reason': f'JSON parsing error: {str(e)}'
        }), 400
    
    # ========================================================================
    # STEP 2: Convert to string for keyword scanning
    # ========================================================================
    # We convert the entire payload to a string so we can search through
    # all fields, nested objects, etc. This is a simple but effective approach
    data_str = str(data)
    
    # ========================================================================
    # STEP 3: Check for banned keywords
    # ========================================================================
    is_banned, keyword = check_for_banned_keywords(data_str)
    if is_banned:
        return jsonify({
            'status': 'BLOCKED',
            'reason': f'Banned keyword detected: "{keyword}"'
        }), 200  # 200 because the API call succeeded, the content was just blocked
    
    # ========================================================================
    # STEP 4: Check for refund amount violations
    # ========================================================================
    is_blocked, amount = check_refund_amount(data)
    if is_blocked:
        return jsonify({
            'status': 'BLOCKED',
            'reason': f'Refund amount ${amount:.2f} exceeds maximum of ${MAX_REFUND_AMOUNT}'
        }), 200
    
    # ========================================================================
    # STEP 5: All checks passed - approve the request
    # ========================================================================
    return jsonify({
        'status': 'APPROVED'
    }), 200


# ============================================================================
# HEALTH CHECK ENDPOINT
# ============================================================================
@app.route('/health', methods=['GET'])
def health_check():
    """
    Simple health check endpoint for monitoring/load balancers.
    
    Interview talking point: Production APIs should have health checks
    for orchestration tools like Kubernetes, ECS, etc.
    """
    return jsonify({'status': 'healthy'}), 200


# ============================================================================
# AUTOMATED TESTING FUNCTION
# ============================================================================
def run_tests():
    """
    Automated test suite that validates the API behavior.
    
    Interview talking points:
    - These are integration tests (testing the full API)
    - In production, would use pytest or unittest framework
    - Would also include unit tests for individual functions
    - CI/CD pipeline would run these automatically
    """
    print("\n" + "="*70)
    print("RUNNING SENTINEL API TESTS")
    print("="*70 + "\n")
    
    # Create a test client - allows us to make requests without running server
    with app.test_client() as client:
        
        # ====================================================================
        # TEST 1: APPROVED - Safe content
        # ====================================================================
        print("TEST 1: Safe content (should be APPROVED)")
        print("-" * 70)
        response = client.post('/api/audit',
                              json={'user': 'john_doe', 'action': 'view_profile', 'refund': 50},
                              content_type='application/json')
        result = response.get_json()
        print(f"Request: {{'user': 'john_doe', 'action': 'view_profile', 'refund': 50}}")
        print(f"Response: {result}")
        print(f"Status Code: {response.status_code}")
        assert result['status'] == 'APPROVED', "Test 1 Failed!"
        print("[OK] PASSED\n")
        
        # ====================================================================
        # TEST 2: BLOCKED - Banned keyword detected
        # ====================================================================
        print("TEST 2: SQL injection attempt (should be BLOCKED)")
        print("-" * 70)
        response = client.post('/api/audit',
                              json={'query': 'DROP TABLE users', 'user': 'hacker'},
                              content_type='application/json')
        result = response.get_json()
        print(f"Request: {{'query': 'DROP TABLE users', 'user': 'hacker'}}")
        print(f"Response: {result}")
        print(f"Status Code: {response.status_code}")
        assert result['status'] == 'BLOCKED', "Test 2 Failed!"
        assert 'DROP TABLE' in result['reason'], "Test 2 Failed - wrong reason!"
        print("[OK] PASSED\n")
        
        # ====================================================================
        # TEST 3: BLOCKED - Refund amount exceeds limit
        # ====================================================================
        print("TEST 3: High refund amount (should be BLOCKED)")
        print("-" * 70)
        response = client.post('/api/audit',
                              json={'customer': 'alice', 'refund_amount': 750, 'reason': 'defective'},
                              content_type='application/json')
        result = response.get_json()
        print(f"Request: {{'customer': 'alice', 'refund_amount': 750, 'reason': 'defective'}}")
        print(f"Response: {result}")
        print(f"Status Code: {response.status_code}")
        assert result['status'] == 'BLOCKED', "Test 3 Failed!"
        assert '750' in result['reason'], "Test 3 Failed - wrong reason!"
        print("[OK] PASSED\n")
        
        # ====================================================================
        # BONUS TEST 4: BLOCKED - Negative sentiment keyword
        # ====================================================================
        print("BONUS TEST 4: Negative sentiment (should be BLOCKED)")
        print("-" * 70)
        response = client.post('/api/audit',
                              json={'customer_message': 'I am angry about this service', 'ticket_id': 123},
                              content_type='application/json')
        result = response.get_json()
        print(f"Request: {{'customer_message': 'I am angry about this service', 'ticket_id': 123}}")
        print(f"Response: {result}")
        print(f"Status Code: {response.status_code}")
        assert result['status'] == 'BLOCKED', "Test 4 Failed!"
        assert 'angry' in result['reason'].lower(), "Test 4 Failed - wrong reason!"
        print("[OK] PASSED\n")
    
    print("="*70)
    print("ALL TESTS PASSED [OK]")
    print("="*70 + "\n")


# ============================================================================
# MAIN EXECUTION
# ============================================================================
# For Vercel Serverless Function, we expose the 'app' object
# Vercel looks for a variable named 'app'
app = app