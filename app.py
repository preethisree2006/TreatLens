"""
Cybersecurity Vulnerability Assessment & Risk Management System
===============================================================
Main Flask Application — Phase 1

Author: Final-Year B.E. CSE Student
Purpose: Academic cybersecurity project demonstrating vulnerability
         assessment workflow in a controlled, authorized environment.

IMPORTANT: This tool is intended ONLY for use against systems
           you are explicitly authorized to test.
"""

import os
from pathlib import Path
from flask import Flask, render_template, redirect, url_for, flash, jsonify
from database.db import db, init_db
from datetime import datetime

# Absolute path to the project root directory
BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------
# Application Factory
# ---------------------------------------------------------------------------

def create_app(config_name=None):
    app = Flask(__name__)

    # --- Configuration ---
    app.config['SECRET_KEY'] = 'cyberproject-phase1-dev-key-change-in-production'
    if config_name == 'testing':
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite://'
    else:
        # Use absolute path so the DB works regardless of working directory
        db_path = BASE_DIR / 'database' / 'database.db'
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['APP_VERSION'] = '1.0.0 — Final'
    app.config['APP_NAME'] = 'ThreatLens — Vulnerability Assessment System'

    # --- Initialize Database ---
    db.init_app(app)

    # --- Register Blueprints ---
    from routes.dashboard import dashboard_bp
    from routes.assessments import assessments_bp
    from routes.scans import scans_bp
    from routes.vulnerabilities import vulnerabilities_bp
    from routes.risk import risk_bp
    from routes.reports import reports_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(assessments_bp)
    app.register_blueprint(scans_bp)
    app.register_blueprint(vulnerabilities_bp)
    app.register_blueprint(risk_bp)
    app.register_blueprint(reports_bp)

    # --- Create tables on first run ---
    with app.app_context():
        init_db(app)

    # --- Context processors (data available to all templates) ---
    @app.context_processor
    def inject_globals():
        return {
            'app_name': app.config['APP_NAME'],
            'app_version': app.config['APP_VERSION'],
            'current_year': datetime.now().year,
        }

    # --- Error handlers ---
    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    return app


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------
app = create_app()

if __name__ == '__main__':
    print("=" * 60)
    print("  ThreatLens — Vulnerability Assessment System")
    print("  Phase 3 — Controlled Vulnerability Scanning")
    print("=" * 60)
    print("  Running at: http://127.0.0.1:5000")
    print("  Press Ctrl+C to stop the server.")
    print("=" * 60)
    app.run(debug=True, host='127.0.0.1', port=5000)
