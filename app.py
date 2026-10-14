import os
import sqlite3
import random
import ipaddress
import csv
import io
import re
import math
import time
import socket
import threading
from functools import wraps
import psutil
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from config import Config
from database.db_handler import init_db, get_db_connection

app = Flask(__name__)
app.config.from_object(Config)

init_db()

NETWORK_SAMPLE_LOCK = threading.Lock()

def serialize_network_samples(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        with NETWORK_SAMPLE_LOCK:
            return view(*args, **kwargs)
    return wrapped

@app.context_processor
def inject_inline_theme():
    """Embed the local stylesheet so the UI stays styled without CDN access."""
    stylesheet_path = os.path.join(app.root_path, 'static', 'css', 'style.css')
    with open(stylesheet_path, encoding='utf-8') as stylesheet:
        return {'netguard_styles': stylesheet.read()}

@app.errorhandler(sqlite3.OperationalError)
def handle_database_operational_error(error):
    app.logger.exception('NetGuard database operation failed')
    message = str(error).lower()
    if 'locked' in message or 'busy' in message:
        if request.path == '/api/network-usage':
            return jsonify({'error': 'NetGuard is waiting for another database update. Retrying automatically.'}), 503
        if request.path.endswith('/block-source'):
            flash('The database is busy with another update. Please retry this alert action.', 'warning')
            return redirect(url_for('alerts'))
        return 'NetGuard is waiting for another database update. Please retry in a moment.', 503
    return 'NetGuard could not complete this database operation. Check the server log for details.', 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['display_name'] = user['display_name'] or user['username']
            
            # Record the successful login
            now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            conn.execute('INSERT INTO access_logs (timestamp, username, action, ip_address) VALUES (?, ?, ?, ?)', 
                         (now, username, 'LOGIN', request.remote_addr))
            conn.commit()
            conn.close()
            
            return redirect(url_for('dashboard'))
        else:
            conn.close()
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout', methods=['POST'])
def logout():
    # Record the logout before clearing the session
    if 'username' in session:
        conn = get_db_connection()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn.execute('INSERT INTO access_logs (timestamp, username, action, ip_address) VALUES (?, ?, ?, ?)', 
                     (now, session['username'], 'LOGOUT', request.remote_addr))
        conn.commit()
        conn.close()
        
    session.clear()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    if user is None:
        conn.close()
        session.clear()
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action', '')
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        if action == 'profile':
            display_name = request.form.get('display_name', '').strip()[:80]
            email = request.form.get('email', '').strip()[:120]
            job_title = request.form.get('job_title', '').strip()[:80]
            department = request.form.get('department', '').strip()[:80]
            phone = request.form.get('phone', '').strip()[:30]
            if not display_name:
                flash('Display name cannot be empty.', 'danger')
            elif email and not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                flash('Enter a valid email address or leave it blank.', 'danger')
            elif phone and not re.fullmatch(r"[0-9+().\-\s]{7,30}", phone):
                flash('Enter a valid phone number or leave it blank.', 'danger')
            else:
                conn.execute('''UPDATE users SET display_name = ?, email = ?, job_title = ?,
                                department = ?, phone = ? WHERE id = ?''',
                             (display_name, email or None, job_title or None, department or None,
                              phone or None, session['user_id']))
                conn.execute('INSERT INTO access_logs (timestamp, username, action, ip_address) VALUES (?, ?, ?, ?)',
                             (now, session['username'], 'PROFILE_UPDATE', request.remote_addr))
                conn.commit()
                session['display_name'] = display_name
                flash('Profile details updated.', 'success')
                conn.close()
                return redirect(url_for('profile'))
        elif action == 'password':
            current_password = request.form.get('current_password', '')
            new_password = request.form.get('new_password', '')
            confirm_password = request.form.get('confirm_password', '')
            if not check_password_hash(user['password_hash'], current_password):
                flash('Current password is incorrect.', 'danger')
            elif len(new_password) < 10:
                flash('New password must be at least 10 characters.', 'danger')
            elif new_password != confirm_password:
                flash('New password and confirmation do not match.', 'danger')
            else:
                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                             (generate_password_hash(new_password), session['user_id']))
                conn.execute('INSERT INTO access_logs (timestamp, username, action, ip_address) VALUES (?, ?, ?, ?)',
                             (now, session['username'], 'PASSWORD_CHANGE', request.remote_addr))
                conn.commit()
                flash('Password changed successfully.', 'success')
                conn.close()
                return redirect(url_for('profile'))
        else:
            flash('Choose a valid profile action.', 'danger')
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    last_login = conn.execute('''SELECT timestamp, ip_address FROM access_logs
                                 WHERE username = ? AND action = 'LOGIN'
                                 ORDER BY id DESC LIMIT 1''', (session['username'],)).fetchone()
    recent_activity = conn.execute('''SELECT timestamp, action, ip_address FROM access_logs
                                      WHERE username = ? ORDER BY id DESC LIMIT 6''',
                                   (session['username'],)).fetchall()
    event_summary = conn.execute('''SELECT COUNT(*) AS total,
                                           SUM(CASE WHEN status != 'RESOLVED' AND severity IN ('HIGH','CRITICAL') THEN 1 ELSE 0 END) AS open_high,
                                           SUM(CASE WHEN status != 'RESOLVED' AND severity = 'CRITICAL' THEN 1 ELSE 0 END) AS open_critical
                                    FROM security_events''').fetchone()
    audit_count = conn.execute('''SELECT COUNT(*) AS total FROM access_logs
                                  WHERE username = ? AND timestamp >= datetime('now', 'localtime', '-30 days')''',
                               (session['username'],)).fetchone()['total']
    conn.close()
    return render_template('profile.html', profile=user, last_login=last_login,
                           recent_activity=recent_activity, event_summary=event_summary,
                           audit_count=audit_count,
                           access_level='Local administrator' if session['username'].lower() == 'admin' else 'Security analyst')

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    ranges = {'24h': '-1 day', '7d': '-7 days', '30d': '-30 days'}
    range_key = request.args.get('range', '7d')
    if range_key not in ranges:
        range_key = '7d'
    range_modifier = ranges[range_key]
    conn = get_db_connection()
    window_stats = conn.execute('''SELECT COUNT(*) AS total,
                                          SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                                          SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
                                          SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') AND status != 'RESOLVED' THEN 1 ELSE 0 END) AS open
                                   FROM security_events WHERE timestamp >= datetime('now', 'localtime', ?)''', (range_modifier,)).fetchone()
    total_events = window_stats['total'] or 0
    critical_alerts = window_stats['critical'] or 0
    high_alerts = window_stats['high'] or 0
    open_alerts = window_stats['open'] or 0
    risk_score = min(100, critical_alerts * 18 + high_alerts * 7 + open_alerts * 4)
    recent = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 5").fetchall()
    bucket = "strftime('%Y-%m-%d %H:00', timestamp)" if range_key == '24h' else 'date(timestamp)'
    trend = conn.execute(f'''SELECT {bucket} AS day, COUNT(*) AS total,
                                   SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical
                            FROM security_events
                            WHERE timestamp >= datetime('now', 'localtime', ?)
                            GROUP BY {bucket} ORDER BY day''', (range_modifier,)).fetchall()
    severity_counts = conn.execute('''SELECT severity, COUNT(*) AS total FROM security_events
                                      WHERE timestamp >= datetime('now', 'localtime', ?)
                                      GROUP BY severity''', (range_modifier,)).fetchall()
    top_sources = conn.execute('''SELECT source_ip, COUNT(*) AS total,
                                         SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                                         COUNT(DISTINCT destination_ip) AS targets,
                                         MAX(timestamp) AS last_seen
                                  FROM security_events
                                  WHERE source_ip IS NOT NULL AND source_ip != ''
                                    AND timestamp >= datetime('now', 'localtime', ?)
                                  GROUP BY source_ip ORDER BY total DESC LIMIT 5''', (range_modifier,)).fetchall()
    bursts = conn.execute('''SELECT source_ip, COUNT(*) AS total, COUNT(DISTINCT destination_ip) AS targets,
                                    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical
                             FROM security_events
                             WHERE source_ip IS NOT NULL AND source_ip != ''
                               AND timestamp >= datetime('now', 'localtime', '-1 hour')
                             GROUP BY source_ip HAVING COUNT(*) >= 3 ORDER BY total DESC LIMIT 5''').fetchall()
    conn.close()
    trend_data = [dict(row) for row in trend]
    
    return render_template('dashboard.html', 
                           username=session.get('display_name', session['username']),
                           total_events=total_events,
                           critical_alerts=critical_alerts,
                           high_alerts=high_alerts,
                           open_alerts=open_alerts,
                           risk_score=risk_score,
                           range_key=range_key,
                           trend=trend_data,
                           severity_counts=[dict(row) for row in severity_counts],
                           top_sources=top_sources,
                           bursts=bursts,
                           recent_events=recent)

@app.route('/alerts')
def alerts():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    search = request.args.get('q', '').strip()[:80]
    severity = request.args.get('severity', '').upper()
    status = request.args.get('status', '').upper()
    where = ["e.severity IN ('HIGH', 'CRITICAL')"]
    params = []
    if severity in {'HIGH', 'CRITICAL'}:
        where.append('e.severity = ?')
        params.append(severity)
    if status in {'DETECTED', 'ACKNOWLEDGED', 'RESOLVED'}:
        where.append('e.status = ?')
        params.append(status)
    if search:
        where.append('(e.source_ip LIKE ? OR e.event_type LIKE ? OR e.description LIKE ?)')
        params.extend([f'%{search}%'] * 3)
    alerts_data = conn.execute(f'''SELECT e.*,
                                          CAST((julianday('now', 'localtime') - julianday(e.timestamp)) * 1440 AS INTEGER) AS age_minutes,
                                          EXISTS(SELECT 1 FROM blacklisted_ips b WHERE b.ip_address = e.source_ip) AS is_blocklisted
                                   FROM security_events e WHERE {' AND '.join(where)}
                                   ORDER BY e.timestamp DESC LIMIT 250''', params).fetchall()
    history = conn.execute('''SELECT incident_history.*, security_events.event_type, security_events.source_ip
                              FROM incident_history JOIN security_events ON security_events.id = incident_history.event_id
                              ORDER BY incident_history.timestamp DESC LIMIT 25''').fetchall()
    conn.close()
    return render_template('alerts.html', alerts=alerts_data, history=history,
                           search=search, severity_filter=severity, status_filter=status)

@app.route('/alerts/<int:event_id>/triage', methods=['POST'])
def triage_alert(event_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    status = request.form.get('status', '').upper()
    note = request.form.get('note', '').strip()[:500]
    if status not in {'ACKNOWLEDGED', 'RESOLVED', 'DETECTED'}:
        flash('Choose a valid incident status.', 'danger')
        return redirect(url_for('alerts'))

    conn = get_db_connection()
    event = conn.execute("SELECT id FROM security_events WHERE id = ? AND severity IN ('HIGH', 'CRITICAL')", (event_id,)).fetchone()
    if event is None:
        conn.close()
        flash('Alert not found.', 'danger')
        return redirect(url_for('alerts'))

    conn.execute('UPDATE security_events SET status = ? WHERE id = ?', (status, event_id))
    conn.execute('''INSERT INTO incident_history (event_id, username, status, note)
                    VALUES (?, ?, ?, ?)''', (event_id, session['username'], status, note))
    conn.commit()
    conn.close()
    flash(f'Alert #{event_id} marked {status.lower()}.', 'success')
    return redirect(url_for('alerts'))

@app.route('/alerts/bulk-triage', methods=['POST'])
def bulk_triage_alerts():
    if 'user_id' not in session: return redirect(url_for('login'))
    status = request.form.get('status', '').upper()
    if status not in {'ACKNOWLEDGED', 'RESOLVED'}:
        flash('Choose a valid bulk action.', 'danger')
        return redirect(url_for('alerts'))
    try:
        event_ids = list(dict.fromkeys(int(value) for value in request.form.getlist('event_ids') if value.isdigit()))[:100]
    except ValueError:
        event_ids = []
    if not event_ids:
        flash('Select at least one alert first.', 'warning')
        return redirect(url_for('alerts'))

    conn = get_db_connection()
    placeholders = ','.join('?' for _ in event_ids)
    selected = conn.execute(f"SELECT id FROM security_events WHERE id IN ({placeholders}) AND severity IN ('HIGH', 'CRITICAL')", event_ids).fetchall()
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    note = request.form.get('note', '').strip()[:500]
    for row in selected:
        conn.execute('UPDATE security_events SET status = ? WHERE id = ?', (status, row['id']))
        conn.execute('INSERT INTO incident_history (event_id, username, status, note) VALUES (?, ?, ?, ?)',
                     (row['id'], session['username'], status, note or 'Bulk triage action.'))
    conn.execute('INSERT INTO access_logs (timestamp, username, action, ip_address) VALUES (?, ?, ?, ?)',
                 (now, session['username'], 'BULK_TRIAGE', request.remote_addr))
    conn.commit()
    conn.close()
    flash(f'{len(selected)} alert(s) marked {status.lower()}.', 'success')
    return redirect(url_for('alerts'))

@app.route('/alerts/export.csv')
def export_alerts_csv():
    if 'user_id' not in session: return redirect(url_for('login'))
    search = request.args.get('q', '').strip()[:80]
    severity = request.args.get('severity', '').upper()
    status = request.args.get('status', '').upper()
    where = ["severity IN ('HIGH', 'CRITICAL')"]
    params = []
    if severity in {'HIGH', 'CRITICAL'}:
        where.append('severity = ?'); params.append(severity)
    if status in {'DETECTED', 'ACKNOWLEDGED', 'RESOLVED'}:
        where.append('status = ?'); params.append(status)
    if search:
        where.append('(source_ip LIKE ? OR event_type LIKE ? OR description LIKE ?)')
        params.extend([f'%{search}%'] * 3)
    conn = get_db_connection()
    events = conn.execute(f"SELECT id, timestamp, source_ip, destination_ip, event_type, severity, status, description, source_kind FROM security_events WHERE {' AND '.join(where)} ORDER BY timestamp DESC", params).fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Origin', 'Source IP', 'Destination IP', 'Event Type', 'Severity', 'Status', 'Description'])
    for event in events:
        values = [event[key] or '' for key in ('id', 'timestamp', 'source_kind', 'source_ip', 'destination_ip', 'event_type', 'severity', 'status', 'description')]
        values = [("'" + value if isinstance(value, str) and value.startswith(('=', '+', '-', '@')) else value) for value in values]
        writer.writerow(values)
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguard_filtered_alerts.csv'})

@app.route('/alerts/<int:event_id>/block-source', methods=['POST'])
def block_alert_source(event_id):
    if 'user_id' not in session: return redirect(url_for('login'))

    conn = get_db_connection()
    # Reserve the writer slot before reading so the later blacklist writes
    # cannot fail with a stale read-to-write upgrade while the monitor polls.
    conn.execute('BEGIN IMMEDIATE')
    event = conn.execute("SELECT id, source_ip, event_type, status FROM security_events WHERE id = ? AND severity IN ('HIGH', 'CRITICAL')", (event_id,)).fetchone()
    if event is None or not event['source_ip']:
        conn.close()
        flash('Alert or source IP not found.', 'danger')
        return redirect(url_for('alerts'))

    try:
        source_ip = str(ipaddress.ip_address(event['source_ip']))
    except ValueError:
        conn.close()
        flash('The alert source is not a valid IP address, so it was not added.', 'danger')
        return redirect(url_for('alerts'))

    existing = conn.execute('SELECT id FROM blacklisted_ips WHERE ip_address = ?', (source_ip,)).fetchone()
    if existing:
        conn.close()
        flash(f'{source_ip} is already on the NetGuard blacklist.', 'warning')
        return redirect(url_for('alerts'))

    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    reason = f"Alert #{event_id}: {event['event_type']}"
    conn.execute('INSERT INTO blacklisted_ips (ip_address, reason, created_at) VALUES (?, ?, ?)', (source_ip, reason, now))
    conn.execute('''INSERT INTO incident_history (event_id, username, status, note)
                    VALUES (?, ?, ?, ?)''', (event_id, session['username'], 'BLOCKLISTED', 'Added source IP to the NetGuard application blacklist.'))
    conn.execute('INSERT INTO access_logs (timestamp, username, action, ip_address) VALUES (?, ?, ?, ?)',
                 (now, session['username'], 'BLACKLIST_FROM_ALERT', request.remote_addr))
    conn.commit()
    conn.close()
    flash(f'{source_ip} added to the NetGuard application blacklist. This does not change your operating system firewall.', 'success')
    return redirect(url_for('alerts'))

@app.route('/logs')
def logs():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    logs_data = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC").fetchall()
    conn.close()
    return render_template('logs.html', logs=logs_data)

@app.route('/ips', methods=['GET', 'POST'])
def ips():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    
    if request.method == 'POST':
        ip_address = request.form['ip_address']
        reason = request.form['reason']
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            conn.execute('INSERT INTO blacklisted_ips (ip_address, reason, created_at) VALUES (?, ?, ?)', (ip_address, reason, now))
            conn.commit()
            flash(f'IP {ip_address} successfully blacklisted.', 'success')
        except sqlite3.IntegrityError:
            flash('This IP is already blacklisted.', 'danger')
            
    blacklisted = conn.execute("SELECT * FROM blacklisted_ips ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('ips.html', ips=blacklisted)

@app.route('/delete_ip/<int:ip_id>', methods=['POST'])
def delete_ip(ip_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    conn.execute('DELETE FROM blacklisted_ips WHERE id = ?', (ip_id,))
    conn.commit()
    conn.close()
    flash('IP address successfully removed from the blacklist.', 'success')
    return redirect(url_for('ips'))

@app.route('/simulation', methods=['GET', 'POST'])
def simulation():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    if request.method == 'POST':
        attack_type = request.form.get('attack_type')
        conn = get_db_connection()
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        if attack_type == 'port_scan':
            conn.execute('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location, source_kind)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'LAB')''', (now, '192.168.1.105', '192.168.1.10', 'TCP', 'Port Scan', 'HIGH', 'Detected rapid connection attempts to 20+ distinct ports.', '💻 Local Network'))
            flash('Simulation: Port Scan alert generated.', 'warning')
            
        elif attack_type == 'traffic_spike':
            conn.execute('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location, source_kind)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'LAB')''', (now, '10.0.0.42', '192.168.1.1', 'UDP', 'Traffic Anomaly', 'CRITICAL', 'Unusual traffic volume: 500+ packets/sec detected.', '🌐 External Threat'))
            flash('Simulation: Traffic Spike alert generated.', 'danger')
            
        elif attack_type == 'suspicious_ip':
            blacklisted = conn.execute('SELECT ip_address FROM blacklisted_ips LIMIT 1').fetchone()
            bad_ip = blacklisted['ip_address'] if blacklisted else '203.0.113.50'
            conn.execute('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location, source_kind)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'LAB')''', (now, bad_ip, '192.168.1.15', 'TCP', 'Blacklist Match', 'HIGH', 'Traffic blocked from known suspicious IP.', '🇷🇺 Russia'))
            flash(f'Simulation: Suspicious activity from {bad_ip} generated.', 'warning')
            
        elif attack_type == 'bulk':
            events_to_insert = []
            event_types = [
                ('Port Scan', 'HIGH', 'Detected rapid connection attempts.', 'TCP'),
                ('Traffic Anomaly', 'CRITICAL', 'Unusual traffic volume detected.', 'UDP'),
                ('Blacklist Match', 'HIGH', 'Traffic blocked from suspicious IP.', 'TCP'),
                ('Malware Signature', 'CRITICAL', 'Known malware payload detected.', 'TCP')
            ]
            locations = ['🇷🇺 Russia', '🇨🇳 China', '🇺🇸 United States', '🇮🇷 Iran', '🇰🇵 North Korea', '🇧🇷 Brazil', '💻 Local Network']
            base_time = datetime.now() - timedelta(hours=2)
            
            for i in range(120):
                evt = random.choice(event_types)
                loc = random.choice(locations)
                src_ip = f"{random.randint(10, 220)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                dst_ip = f"192.168.1.{random.randint(1, 50)}"
                base_time += timedelta(seconds=random.randint(10, 60))
                time_str = base_time.strftime('%Y-%m-%d %H:%M:%S')
                events_to_insert.append((time_str, src_ip, dst_ip, evt[3], evt[0], evt[1], evt[2], loc, 'LAB'))
                
            conn.executemany('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location, source_kind)
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''', events_to_insert)
            flash('Simulation: Generated 120 bulk security events with Geo-IP data.', 'success')

        conn.commit()
        conn.close()
        return redirect(url_for('simulation'))
        
    return render_template('simulation.html')

@app.route('/reports')
def reports():
    if 'user_id' not in session: return redirect(url_for('login'))
    search = request.args.get('q', '').strip()[:100]
    action = request.args.get('action', '').upper()
    window = request.args.get('window', '7d')
    windows = {'24h': '-1 day', '7d': '-7 days', '30d': '-30 days', 'all': None}
    if window not in windows: window = '7d'
    clauses, params = [], []
    if windows[window]:
        clauses.append("timestamp >= datetime('now', 'localtime', ?)")
        params.append(windows[window])
    if action in {'LOGIN', 'LOGOUT', 'PROFILE_UPDATE', 'PASSWORD_CHANGE', 'BLACKLIST_FROM_ALERT'}:
        clauses.append('action = ?')
        params.append(action)
    else:
        action = ''
    if search:
        clauses.append('(username LIKE ? OR ip_address LIKE ? OR action LIKE ?)')
        params.extend([f'%{search}%'] * 3)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    conn = get_db_connection()
    access_logs = conn.execute(f"SELECT * FROM access_logs {where} ORDER BY timestamp DESC LIMIT 500", params).fetchall()
    conn.close()
    return render_template('reports.html', access_logs=access_logs, audit_search=search,
                           audit_action=action, audit_window=window, audit_count=len(access_logs))

@app.route('/reports/audit.csv')
def export_audit_csv():
    if 'user_id' not in session: return redirect(url_for('login'))
    search = request.args.get('q', '').strip()[:100]
    action = request.args.get('action', '').upper()
    window = request.args.get('window', '7d')
    windows = {'24h': '-1 day', '7d': '-7 days', '30d': '-30 days', 'all': None}
    if window not in windows: window = '7d'
    clauses, params = [], []
    if windows[window]:
        clauses.append("timestamp >= datetime('now', 'localtime', ?)")
        params.append(windows[window])
    if action in {'LOGIN', 'LOGOUT', 'PROFILE_UPDATE', 'PASSWORD_CHANGE', 'BLACKLIST_FROM_ALERT'}:
        clauses.append('action = ?'); params.append(action)
    if search:
        clauses.append('(username LIKE ? OR ip_address LIKE ? OR action LIKE ?)')
        params.extend([f'%{search}%'] * 3)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    conn = get_db_connection()
    logs = conn.execute(f"SELECT timestamp, username, action, ip_address FROM access_logs {where} ORDER BY timestamp DESC", params).fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Username', 'Action', 'Connecting IP'])
    for row in logs:
        writer.writerow([row['timestamp'], row['username'], row['action'], row['ip_address']])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguard_audit_log.csv'})

@app.route('/monitor', methods=['GET', 'POST'])
def monitor():
    if 'user_id' not in session: return redirect(url_for('login'))
    username = session['username']
    if request.method == 'POST':
        try:
            quota = float(request.form.get('monthly_quota_gb', ''))
        except (TypeError, ValueError):
            quota = 0
        if not math.isfinite(quota) or quota < 0.1 or quota > 10000:
            flash('Monthly data limit must be between 0.1 and 10,000 GB.', 'danger')
        else:
            conn = get_db_connection()
            conn.execute('INSERT OR IGNORE INTO data_usage_settings (username, monthly_quota_gb) VALUES (?, 10)', (username,))
            conn.execute('UPDATE data_usage_settings SET monthly_quota_gb = ? WHERE username = ?', (quota, username))
            conn.commit()
            conn.close()
            flash('Monthly data limit updated.', 'success')
        return redirect(url_for('monitor'))
    conn = get_db_connection()
    quota_row = conn.execute('SELECT monthly_quota_gb FROM data_usage_settings WHERE username = ?', (username,)).fetchone()
    quota = quota_row['monthly_quota_gb'] if quota_row else 10
    conn.close()
    return render_template('monitor.html', quota_gb=float(quota))

@app.route('/api/network-usage')
@serialize_network_samples
def api_network_usage():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    now = datetime.now()
    today = now.date().isoformat()
    month_start = now.date().replace(day=1).isoformat()
    counters = psutil.net_io_counters(pernic=True, nowrap=True) or {}
    stats = psutil.net_if_stats()
    conn = get_db_connection()
    conn.execute('BEGIN IMMEDIATE')
    baselines = {
        row['interface_name']: row
        for row in conn.execute('SELECT interface_name, bytes_sent, bytes_recv, sampled_at FROM network_interface_state')
    }
    daily_totals = {
        row['interface_name']: row
        for row in conn.execute('''SELECT interface_name, SUM(upload_bytes) AS upload, SUM(download_bytes) AS download
                                   FROM network_usage_daily WHERE usage_date=? GROUP BY interface_name''', (today,))
    }
    monthly_totals = {
        row['interface_name']: row
        for row in conn.execute('''SELECT interface_name, SUM(upload_bytes) AS upload, SUM(download_bytes) AS download
                                   FROM network_usage_daily WHERE usage_date>=? AND usage_date<=? GROUP BY interface_name''',
                                (month_start, today))
    }
    interfaces = []
    state_updates = []
    usage_updates = []
    for name, counter in counters.items():
        # Loopback traffic is not useful as a physical network measurement.
        if name.lower() in {'lo', 'loopback'}:
            continue
        state = baselines.get(name)
        sent_delta = recv_delta = 0
        elapsed = 0
        if state:
            elapsed = max(0.001, time.time() - datetime.fromisoformat(state['sampled_at']).timestamp())
            if counter.bytes_sent >= state['bytes_sent']:
                sent_delta = counter.bytes_sent - state['bytes_sent']
            if counter.bytes_recv >= state['bytes_recv']:
                recv_delta = counter.bytes_recv - state['bytes_recv']
        sampled_at = now.isoformat(timespec='seconds')
        state_updates.append((name, counter.bytes_sent, counter.bytes_recv, sampled_at))
        if sent_delta or recv_delta:
            usage_updates.append((today, name, sent_delta, recv_delta))
        daily = daily_totals.get(name)
        monthly = monthly_totals.get(name)
        adapter = stats.get(name)
        interfaces.append({
            'name': name, 'is_up': bool(adapter and adapter.isup),
            'speed_mbps': round(adapter.speed, 1) if adapter and adapter.speed else None,
            'upload_mbps': round((sent_delta * 8 / elapsed / 1_000_000), 3) if elapsed else 0,
            'download_mbps': round((recv_delta * 8 / elapsed / 1_000_000), 3) if elapsed else 0,
            'upload_bytes': int((daily['upload'] if daily else 0) or 0) + sent_delta,
            'download_bytes': int((daily['download'] if daily else 0) or 0) + recv_delta,
            'month_upload_bytes': int((monthly['upload'] if monthly else 0) or 0) + sent_delta,
            'month_download_bytes': int((monthly['download'] if monthly else 0) or 0) + recv_delta,
            'initialized': state is not None
        })
    conn.executemany('''INSERT INTO network_interface_state(interface_name, bytes_sent, bytes_recv, sampled_at)
                        VALUES (?, ?, ?, ?) ON CONFLICT(interface_name) DO UPDATE SET
                        bytes_sent=excluded.bytes_sent, bytes_recv=excluded.bytes_recv, sampled_at=excluded.sampled_at''', state_updates)
    conn.executemany('''INSERT INTO network_usage_daily(usage_date, interface_name, upload_bytes, download_bytes)
                        VALUES (?, ?, ?, ?) ON CONFLICT(usage_date, interface_name) DO UPDATE SET
                        upload_bytes=upload_bytes+excluded.upload_bytes,
                        download_bytes=download_bytes+excluded.download_bytes''', usage_updates)
    conn.commit()
    conn.close()
    interfaces.sort(key=lambda item: (not item['is_up'], item['name'].lower()))
    return jsonify({'sampled_at': now.isoformat(timespec='seconds'), 'interfaces': interfaces})

@app.route('/connections')
def live_connections():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('connections.html')

@app.route('/api/live-connections')
def api_live_connections():
    if 'user_id' not in session:
        return jsonify({'error': 'Authentication required'}), 401
    try:
        sockets = psutil.net_connections(kind='inet')
    except psutil.AccessDenied:
        return jsonify({'error': 'The NetGuard process cannot inspect the Windows socket table. Start NetGuard from an elevated Windows terminal to view the full inventory.'}), 403
    except (OSError, psutil.Error):
        app.logger.exception('Unable to read the local socket table')
        return jsonify({'error': 'Windows could not provide the current socket table.'}), 503

    watched_service_ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 445: 'SMB',
                             3389: 'RDP', 5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM TLS'}
    rows = []
    for item in sockets:
        local = item.laddr
        remote = item.raddr
        local_ip = local.ip if hasattr(local, 'ip') else (local[0] if local else '')
        local_port = local.port if hasattr(local, 'port') else (local[1] if local else 0)
        remote_ip = remote.ip if hasattr(remote, 'ip') else (remote[0] if remote else '')
        remote_port = remote.port if hasattr(remote, 'port') else (remote[1] if remote else 0)
        family = 'IPv6' if item.family == socket.AF_INET6 else 'IPv4'
        protocol = 'TCP' if item.type == socket.SOCK_STREAM else 'UDP'
        state = item.status or ('BOUND' if local else 'UNKNOWN')
        process_name = 'System / unknown'
        if item.pid:
            try:
                process_name = psutil.Process(item.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_name = 'Protected / exited process'
        flags = []
        bind_all = state == psutil.CONN_LISTEN and local_ip in {'0.0.0.0', '::'}
        if state == psutil.CONN_LISTEN:
            if bind_all:
                flags.append({'label': 'Bound to all interfaces', 'kind': 'review'})
            else:
                flags.append({'label': 'Listening', 'kind': 'neutral'})
            service = watched_service_ports.get(local_port)
            if service and bind_all:
                flags.append({'label': f'{service} listener · review', 'kind': 'review'})
        elif remote_ip:
            try:
                if ipaddress.ip_address(remote_ip).is_global:
                    flags.append({'label': 'Public remote peer', 'kind': 'neutral'})
            except ValueError:
                pass
        local_display = f'[{local_ip}]:{local_port}' if ':' in local_ip else f'{local_ip}:{local_port}'
        remote_display = (f'[{remote_ip}]:{remote_port}' if ':' in remote_ip else f'{remote_ip}:{remote_port}') if remote_ip else '—'
        rows.append({
            'protocol': protocol, 'family': family, 'state': state,
            'pid': item.pid, 'process': process_name,
            'local': local_display, 'remote': remote_display,
            'local_port': local_port, 'flags': flags
        })
    rows.sort(key=lambda row: (0 if row['state'] == 'LISTEN' else 1, row['process'].lower(), row['local_port']))
    summary = {
        'total': len(rows),
        'listening': sum(row['state'] == 'LISTEN' for row in rows),
        'established': sum(row['state'] == 'ESTABLISHED' for row in rows),
        'review': sum(any(flag['kind'] == 'review' for flag in row['flags']) for row in rows)
    }
    return jsonify({'sampled_at': datetime.now().isoformat(timespec='seconds'), 'summary': summary, 'connections': rows})

@app.route('/connections/export.csv')
def export_live_connections():
    if 'user_id' not in session: return redirect(url_for('login'))
    response = api_live_connections()
    if isinstance(response, tuple):
        return response
    payload = response.get_json()
    if response.status_code != 200:
        return response
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Sampled at', 'Protocol', 'Family', 'State', 'PID', 'Process', 'Local endpoint', 'Remote endpoint', 'Review flags'])
    for row in payload['connections']:
        writer.writerow([payload['sampled_at'], row['protocol'], row['family'], row['state'], row['pid'], row['process'], row['local'], row['remote'], '; '.join(flag['label'] for flag in row['flags'])])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguard_live_connections.csv'})

@app.route('/monitor/export.csv')
def export_usage_csv():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    rows = conn.execute('''SELECT usage_date, interface_name, upload_bytes, download_bytes
                           FROM network_usage_daily ORDER BY usage_date DESC, interface_name''').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Date', 'Network adapter', 'Upload bytes', 'Download bytes', 'Total bytes'])
    for row in rows:
        writer.writerow([row['usage_date'], row['interface_name'], row['upload_bytes'], row['download_bytes'], row['upload_bytes'] + row['download_bytes']])
    return Response(output.getvalue(), mimetype='text/csv',
                    headers={'Content-Disposition': 'attachment; filename=netguard_network_usage.csv'})

@app.route('/export_csv')
def export_csv():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    events = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC").fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ID', 'Timestamp', 'Origin', 'Source IP', 'Destination IP', 'Protocol', 'Event Type', 'Severity', 'Location', 'Description', 'Status'])
    for event in events:
        writer.writerow([event['id'], event['timestamp'], event['source_kind'], event['source_ip'], event['destination_ip'], event['protocol'], event['event_type'], event['severity'], event['location'], event['description'], event['status']])
    return Response(output.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguard_report.csv'})

@app.route('/pdf_report')
def pdf_report():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    events = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC").fetchall()
    conn.close()
    
    return render_template('pdf_report.html', events=events)

@app.route('/clear_data', methods=['POST'])
def clear_data():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM security_events')
    conn.execute('DELETE FROM sqlite_sequence WHERE name="security_events"')
    conn.commit()
    conn.close()
    
    flash('System Reset: All security events and logs have been cleared.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/api/threats')
def api_threats():
    if 'user_id' not in session: 
        return jsonify({'error': 'Unauthorized. Please login.'}), 401
    
    ranges = {'24h': '-1 day', '7d': '-7 days', '30d': '-30 days'}
    range_key = request.args.get('range', '7d')
    if range_key not in ranges: range_key = '7d'
    conn = get_db_connection()
    events = conn.execute("SELECT * FROM security_events WHERE timestamp >= datetime('now', 'localtime', ?) ORDER BY timestamp DESC LIMIT 50", (ranges[range_key],)).fetchall()
    stats = conn.execute('''SELECT COUNT(*) AS total,
                                   SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) AS high,
                                   SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical,
                                   SUM(CASE WHEN severity IN ('HIGH', 'CRITICAL') AND status != 'RESOLVED' THEN 1 ELSE 0 END) AS open
                            FROM security_events WHERE timestamp >= datetime('now', 'localtime', ?)''', (ranges[range_key],)).fetchone()
    trend_bucket = "strftime('%Y-%m-%d %H:00', timestamp)" if range_key == '24h' else 'date(timestamp)'
    trend = conn.execute(f'''SELECT {trend_bucket} AS day, COUNT(*) AS total,
                                   SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) AS critical
                            FROM security_events WHERE timestamp >= datetime('now', 'localtime', ?)
                            GROUP BY {trend_bucket} ORDER BY day''', (ranges[range_key],)).fetchall()
    severity_counts = conn.execute('''SELECT severity, COUNT(*) AS total FROM security_events
                                     WHERE timestamp >= datetime('now', 'localtime', ?)
                                     GROUP BY severity''', (ranges[range_key],)).fetchall()
    conn.close()
    
    events_list = [dict(row) for row in events]
    
    return jsonify({
        'status': 'success',
        'total_returned': len(events_list),
        'stats': {'total': stats['total'] or 0, 'high': stats['high'] or 0,
                  'critical': stats['critical'] or 0, 'open': stats['open'] or 0,
                  'risk': min(100, (stats['critical'] or 0) * 18 + (stats['high'] or 0) * 7 + (stats['open'] or 0) * 4)},
        'trend': [dict(row) for row in trend],
        'severity_counts': [dict(row) for row in severity_counts],
        'data': events_list
    })

if __name__ == '__main__':
    app.run(debug=True)
