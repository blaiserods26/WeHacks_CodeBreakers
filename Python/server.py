from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials
import os
import json
from flask import Flask, request, redirect, session, url_for, jsonify, send_from_directory

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key

# OAuth 2.0 configuration
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRETS_FILE = "./credentials.json"

@app.route('/')
def index():
    """Serve the HTML file for the frontend."""
    return send_from_directory('static', 'index.html')

@app.route('/authorize')
def authorize():
    """Start the OAuth flow."""
    try:
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        authorization_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true'
        )
        
        session['state'] = state
        return redirect(authorization_url)
    
    except Exception as e:
        return f"Error starting OAuth flow: {str(e)}"

@app.route('/oauth2callback')
def oauth2callback():
    """Handle the OAuth 2.0 callback."""
    try:
        state = session['state']
        
        flow = Flow.from_client_secrets_file(
            CLIENT_SECRETS_FILE,
            scopes=SCOPES,
            state=state,
            redirect_uri=url_for('oauth2callback', _external=True)
        )
        
        # Use the authorization server's response to fetch the OAuth 2.0 tokens
        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)
        
        credentials = flow.credentials
        
        # Save credentials
        save_credentials(credentials)
        
        return redirect(url_for('analyze_emails'))
    
    except Exception as e:
        return f"Error in OAuth callback: {str(e)}"

def save_credentials(credentials):
    """Save credentials to a file."""
    creds_data = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    
    with open('token.json', 'w') as token_file:
        json.dump(creds_data, token_file)

@app.route('/analyze_emails')
def analyze_emails():
    """Analyze emails using saved credentials."""
    try:
        # Load saved credentials
        with open('token.json', 'r') as token_file:
            creds_data = json.load(token_file)
        
        # Import the email analysis function
        from email_security_tool import analyze_emails
        
        # Run the analysis
        results = analyze_emails(creds_data)
        
        return jsonify(results)
    
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/emails', methods=['GET'])
def get_emails():
    """Endpoint to get the list of emails."""
    try:
        # Load saved credentials
        with open('token.json', 'r') as token_file:
            creds_data = json.load(token_file)
        
        # Import the email fetching function
        from email_security_tool import fetch_emails
        
        # Fetch the emails
        emails = fetch_emails(creds_data)
        
        return jsonify(emails)
    
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
    app.run(debug=True, port=5000)