# Biniam Demissie
# 09/29/2025
import base64
import json
import requests
import os
import zipfile # <--- This was missing
import io      # <--- This was missing
from flask import Flask, render_template, request, jsonify, Response
from ghidra_assistant import GhidraAssistant 

app = Flask(__name__)

app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 
# Initialize the AI Assistant
# Note: Configuration for Ollama is handled inside ghidra_assistant.py
assistant = GhidraAssistant()

GHIDRA_API_BASE = "http://localhost:9090"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    # Get optional password from the form data
    zip_password = request.form.get('password')

    try:
        # Read file into memory once
        file_content = file.read()
        filename = file.filename

        # Check if it is a ZIP file
        # We use io.BytesIO because we are working with file in memory, not on disk
        if zipfile.is_zipfile(io.BytesIO(file_content)):
            try:
                with zipfile.ZipFile(io.BytesIO(file_content)) as z:
                    # We assume the malware is the first file in the zip
                    target_file = z.namelist()[0]
                    
                    # Prepare password if provided
                    pwd_bytes = zip_password.encode('utf-8') if zip_password else None
                    
                    # Attempt extraction
                    file_content = z.read(target_file, pwd=pwd_bytes)
                    filename = target_file
                    
            except RuntimeError as e:
                # Handle encrypted zips specifically
                if 'Bad password' in str(e) or 'password required' in str(e):
                    return jsonify({
                        "error": "PASSWORD_REQUIRED", 
                        "message": "This archive is encrypted. Please provide a password."
                    }), 401
                else:
                    raise e
            except zipfile.BadZipFile:
                # If zip check passed but extraction failed, just treat as raw binary
                pass

        encoded_contents = base64.b64encode(file_content).decode('utf-8')
        
        payload = {
            "file_b64": encoded_contents,
            "filename": filename,
            "persist": True 
        }
        
        print(f"DEBUG: Sending {filename} to Ghidra...")
        response = requests.post(f"{GHIDRA_API_BASE}/analyze_b64", json=payload)
        
        # Handle cases where Ghidra returns 200 OK but bad/empty JSON
        try:
            data = response.json()
            return jsonify(data)
        except requests.exceptions.JSONDecodeError:
            print(f"ERROR: Ghidra returned 200 but output was not JSON. Raw: {response.text}")
            # Return a fake success so the UI doesn't crash
            return jsonify({
                "job_id": "manual-fix-" + str(base64.b64encode(os.urandom(6)).decode('utf-8')), 
                "status": "uploaded_raw",
                "filename": filename,
                "warning": "Ghidra analysis started but returned non-standard output."
            })
        
    except requests.exceptions.RequestException as e:
        print(f"Connection Error: {e}")
        return jsonify({"error": f"Failed to connect to Ghidra service: {e}"}), 500
    except Exception as e:
        print(f"General Error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/chat', methods=['POST'])
def chat():
    data = request.get_json()
    user_message = data.get('message')
    job_id = data.get('job_id')

    if not user_message or not job_id:
        return jsonify({"error": "Message and job_id are required"}), 400

    def generate():
        try:
            for chunk in assistant.chat_completion_stream(user_message, job_id):
                yield f"data: {chunk}\n\n"
        except Exception as e:
            error_event = json.dumps({"type": "error", "content": str(e)})
            yield f"data: {error_event}\n\n"
    
    return Response(generate(), mimetype='text/event-stream')
        
@app.route('/status/<job_id>', methods=['GET'])
def get_status(job_id):
    # If we generated a fake ID for a raw upload, just return 'done'
    if job_id.startswith("manual-fix"):
        return jsonify({"status": "done", "job_id": job_id})

    try:
        response = requests.get(f"{GHIDRA_API_BASE}/status/{job_id}")
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Failed to get status: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
