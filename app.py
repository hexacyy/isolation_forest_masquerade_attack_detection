from flask import Flask, request, jsonify, redirect, url_for, session
from dotenv import load_dotenv
import os
from logging_config import setup_logging

# Load environment variables and setup logging
load_dotenv("webhook.env")
setup_logging()

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ["SECRET_KEY"]
    
    # Register blueprints
    from routes.auth import auth_bp
    from routes.prediction import prediction_bp
    from routes.dashboard import dashboard_bp
    from routes.admin import admin_bp
    from routes.data_feeds import data_feeds_bp
    from routes.ml_performance import ml_performance_bp  # ADD THIS LINE
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(prediction_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(data_feeds_bp)
    app.register_blueprint(ml_performance_bp)  # ADD THIS LINE
    
    # Context processor for template variables
    @app.context_processor
    def inject_environment():
        return dict(is_azure='azurewebsites.net' in request.host)
    
    # Root route redirect
    @app.route('/')
    def index():
        if 'username' in session:
            return redirect(url_for('dashboard.dashboard'))
        else:
            return redirect(url_for('auth.login'))
    
    # Health check endpoint
    @app.route('/health')
    def health_check():
        return {"status": "healthy", "service": "anomaly_detection"}, 200
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "error": "Not Found", 
            "message": "The requested resource was not found on this server.",
            "status_code": 404
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return jsonify({
            "error": "Internal Server Error",
            "message": "An unexpected error occurred on the server.",
            "status_code": 500
        }), 500
    
    return app

if __name__ == '__main__':
    app = create_app()
    
    # Development server configuration
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')
    
    print(f"Starting Flask application on {host}:{port} (debug={debug_mode})")
    app.run(host=host, port=port, debug=debug_mode)