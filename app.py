"""
app.py - Flask Web Application for Secure Key Management Micro Project
College DSP Micro Project:
"Secure Key Management for AI/ML Applications with Automatic Key Rotation"
"""

from flask import Flask, render_template, request, jsonify
import key_manager

app = Flask(__name__)


@app.route("/")
def index():
    """Render the dashboard UI."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def api_status():
    """
    Returns current dashboard state and triggers key rotation if expired.
    Polled periodically by the dashboard frontend.
    """
    state = key_manager.get_dashboard_state()
    return jsonify(state)


@app.route("/api/generate-key", methods=["POST"])
def api_generate_key():
    """Generate a new cryptographic key."""
    result = key_manager.generate_key()
    return jsonify(result)


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    """Encrypt sensitive AI/ML data."""
    payload = request.get_json(silent=True) or {}
    plaintext = payload.get("data", "")
    result = key_manager.encrypt_data(plaintext)
    return jsonify(result)


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    """Decrypt the stored ciphertext."""
    result = key_manager.decrypt_data()
    return jsonify(result)


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    """
    Manual / Forced Key Rotation.
    Provides immediate key rotation for instant demonstration and verification.
    """
    result = key_manager.rotate_key(automatic=False)
    return jsonify(result)


@app.route("/api/delete-key", methods=["POST"])
def api_delete_key():
    """Delete / invalidate the active key."""
    result = key_manager.delete_key()
    return jsonify(result)


@app.route("/api/test-wrong-key", methods=["POST"])
def api_test_wrong_key():
    """Test unauthorized access attempt with a fake/wrong key."""
    result = key_manager.test_unauthorized_access()
    return jsonify(result)


if __name__ == "__main__":
    print("=" * 60)
    print("  Secure Key Management for AI/ML Applications")
    print("  Automatic Key Rotation Micro Project")
    print("  Running on: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(host="127.0.0.1", port=5000, debug=True)
