from datetime import datetime
import os
from flask import render_template, url_for, flash, redirect, request, abort, jsonify
from app import app, db, bcrypt
from forms import RegistrationForm, LoginForm, UploadLogForm, AlertResolutionForm
from models import User, IngestedDataLog, ThreatAlert, ThreatIntelligence
from flask_login import login_user, current_user, logout_user, login_required
from werkzeug.utils import secure_filename
from config import Config
from data_ingestion.simulate_ingestion import process_ingested_data, simulate_training_data
import json

# --- Application Routes ---

@app.before_request
def initialize_ml_models_and_threat_intel():
    # This runs before the first request.
    # In a production system, model loading and initial threat intel sync
    # would be managed by a separate service or container, or carefully within Gunicorn hooks.
    if not hasattr(app, 'ml_initialized'):
        with app.app_context():
            simulate_training_data()
        app.ml_initialized = True
        print("ML Models and Threat Intel initialized for the first time.")


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_LOG_EXTENSIONS

@app.route("/")
@app.route("/home")
def home():
    return render_template('index.html', title='Home')

@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(username=form.username.data, email=form.email.data)
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            flash('Login successful!', 'success')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

@app.route("/dashboard")
@login_required
def dashboard():
    total_alerts = ThreatAlert.query.count()
    unresolved_alerts = ThreatAlert.query.filter_by(is_resolved=False).count()
    recent_alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).limit(10).all()
    # For charts, you'd aggregate data:
    # alert_types_count = db.session.query(ThreatAlert.alert_type, db.func.count(ThreatAlert.id)).group_by(ThreatAlert.alert_type).all()
    # severity_count = db.session.query(ThreatAlert.severity, db.func.count(ThreatAlert.id)).group_by(ThreatAlert.severity).all()

    return render_template('dashboard.html',
                           title='Dashboard',
                           total_alerts=total_alerts,
                           unresolved_alerts=unresolved_alerts,
                           recent_alerts=recent_alerts)

@app.route("/ingest_data", methods=['GET', 'POST'])
@login_required
def ingest_data():
    form = UploadLogForm()
    if form.validate_on_submit():
        if 'log_file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        file = request.files['log_file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            upload_path = os.path.join(app.root_path, Config.UPLOAD_FOLDER, filename)
            file.save(upload_path)

            source_type = form.source_type.data
            file_content_preview = file.read(200).decode('utf-8', errors='ignore') # Read first 200 bytes for summary
            file.seek(0) # Reset file pointer for actual processing

            # This is a synchronous call for simplicity. In production, use Celery/Redis for background tasks.
            num_alerts = process_ingested_data(upload_path, source_type, current_user.id, data_summary=file_content_preview)

            flash(f'Data ingested successfully from {filename}. {num_alerts} potential threats identified.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash(f'Invalid file type. Allowed extensions are {", ".join(Config.ALLOWED_LOG_EXTENSIONS)}.', 'danger')
            return redirect(request.url)
    return render_template('upload_log.html', title='Ingest Data', form=form)

@app.route("/alerts")
@login_required
def alerts():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    all_alerts = ThreatAlert.query.order_by(ThreatAlert.timestamp.desc()).paginate(page=page, per_page=per_page)
    return render_template('alerts.html', title='All Alerts', alerts=all_alerts)


@app.route("/alert/<int:alert_id>", methods=['GET', 'POST'])
@login_required
def threat_detail(alert_id):
    alert = ThreatAlert.query.get_or_404(alert_id)
    form = AlertResolutionForm()

    if form.validate_on_submit() and not alert.is_resolved:
        alert.is_resolved = True
        alert.resolved_by_user_id = current_user.id
        alert.resolved_timestamp = datetime.utcnow()
        alert.description += f"\n[Resolved by {current_user.username} on {alert.resolved_timestamp.strftime('%Y-%m-%d %H:%M:%S')}]"
        if form.comment.data:
            alert.description += f"\nResolution Comment: {form.comment.data}"
        db.session.commit()
        flash('Alert marked as resolved!', 'success')
        return redirect(url_for('threat_detail', alert_id=alert.id))
    
    details = alert.get_details()
    return render_template('threat_detail.html', title='Alert Details', alert=alert, details=details, form=form)

@app.route("/threat_intelligence")
@login_required
def threat_intelligence():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    all_iocs = ThreatIntelligence.query.order_by(ThreatIntelligence.last_updated.desc()).paginate(page=page, per_page=per_page)
    return render_template('threat_intel.html', title='Threat Intelligence', iocs=all_iocs)

@app.route("/reports")
@login_required
def reports():
    # Example reporting data (would be more complex in real app)
    total_alerts_by_type = db.session.query(ThreatAlert.alert_type, db.func.count(ThreatAlert.id)).group_by(ThreatAlert.alert_type).all()
    total_alerts_by_severity = db.session.query(ThreatAlert.severity, db.func.count(ThreatAlert.id)).group_by(ThreatAlert.severity).all()
    
    # Convert results to dictionaries for easier template access
    alerts_by_type = {item[0]: item[1] for item in total_alerts_by_type}
    alerts_by_severity = {item[0]: item[1] for item in total_alerts_by_severity}

    return render_template('report.html',
                           title='Reports',
                           alerts_by_type=alerts_by_type,
                           alerts_by_severity=alerts_by_severity)

# API endpoint for chart data (example)
@app.route("/api/alert_counts_by_type")
@login_required
def api_alert_counts_by_type():
    data = db.session.query(ThreatAlert.alert_type, db.func.count(ThreatAlert.id)).group_by(ThreatAlert.alert_type).all()
    labels = [row[0] for row in data]
    values = [row[1] for row in data]
    return jsonify({"labels": labels, "values": values})

@app.route("/api/alert_counts_by_severity")
@login_required
def api_alert_counts_by_severity():
    data = db.session.query(ThreatAlert.severity, db.func.count(ThreatAlert.id)).group_by(ThreatAlert.severity).all()
    # Ensure consistent order for severities if needed (e.g., Critical, High, Medium, Low)
    severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    sorted_data = sorted(data, key=lambda x: severity_order.get(x[0], 0), reverse=True)
    labels = [row[0] for row in sorted_data]
    values = [row[1] for row in sorted_data]
    return jsonify({"labels": labels, "values": values})