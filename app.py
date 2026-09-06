import os
import sqlite3
import random
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, Response, jsonify
from werkzeug.security import check_password_hash
from config import Config
from database.db_handler import init_db, get_db_connection

app = Flask(__name__)
app.config.from_object(Config)

init_db()

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

@app.route('/logout')
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

@app.route('/')
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    total_events = conn.execute("SELECT COUNT(*) as c FROM security_events").fetchone()['c']
    critical_alerts = conn.execute("SELECT COUNT(*) as c FROM security_events WHERE severity = 'CRITICAL'").fetchone()['c']
    high_alerts = conn.execute("SELECT COUNT(*) as c FROM security_events WHERE severity = 'HIGH'").fetchone()['c']
    recent = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 5").fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                           username=session['username'],
                           total_events=total_events,
                           critical_alerts=critical_alerts,
                           high_alerts=high_alerts,
                           recent_events=recent)

@app.route('/alerts')
def alerts():
    if 'user_id' not in session: return redirect(url_for('login'))
    conn = get_db_connection()
    alerts_data = conn.execute("SELECT * FROM security_events WHERE severity IN ('HIGH', 'CRITICAL') ORDER BY timestamp DESC").fetchall()
    conn.close()
    return render_template('alerts.html', alerts=alerts_data)

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
            conn.execute('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (now, '192.168.1.105', '192.168.1.10', 'TCP', 'Port Scan', 'HIGH', 'Detected rapid connection attempts to 20+ distinct ports.', '💻 Local Network'))
            flash('Simulation: Port Scan alert generated.', 'warning')
            
        elif attack_type == 'traffic_spike':
            conn.execute('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (now, '10.0.0.42', '192.168.1.1', 'UDP', 'Traffic Anomaly', 'CRITICAL', 'Unusual traffic volume: 500+ packets/sec detected.', '🌐 External Threat'))
            flash('Simulation: Traffic Spike alert generated.', 'danger')
            
        elif attack_type == 'suspicious_ip':
            blacklisted = conn.execute('SELECT ip_address FROM blacklisted_ips LIMIT 1').fetchone()
            bad_ip = blacklisted['ip_address'] if blacklisted else '203.0.113.50'
            conn.execute('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location) 
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', (now, bad_ip, '192.168.1.15', 'TCP', 'Blacklist Match', 'HIGH', 'Traffic blocked from known suspicious IP.', '🇷🇺 Russia'))
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
                events_to_insert.append((time_str, src_ip, dst_ip, evt[3], evt[0], evt[1], evt[2], loc))
                
            conn.executemany('''INSERT INTO security_events (timestamp, source_ip, destination_ip, protocol, event_type, severity, description, location) 
                             VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', events_to_insert)
            flash('Simulation: Generated 120 bulk security events with Geo-IP data.', 'success')

        conn.commit()
        conn.close()
        return redirect(url_for('simulation'))
        
    return render_template('simulation.html')

@app.route('/reports')
def reports():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    # Fetch access logs for the reports page
    conn = get_db_connection()
    access_logs = conn.execute("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 20").fetchall()
    conn.close()
    
    return render_template('reports.html', access_logs=access_logs)

@app.route('/monitor')
def monitor():
    if 'user_id' not in session: return redirect(url_for('login'))
    return render_template('monitor.html')

@app.route('/export_csv')
def export_csv():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    events = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC").fetchall()
    conn.close()
    
    def generate():
        yield 'ID,Timestamp,Source IP,Destination IP,Protocol,Event Type,Severity,Location,Description,Status\n'
        for e in events:
            yield f"{e['id']},{e['timestamp']},{e['source_ip']},{e['destination_ip']},{e['protocol']},{e['event_type']},{e['severity']},\"{e['location']}\",\"{e['description']}\",{e['status']}\n"
            
    return Response(generate(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=netguard_report.csv'})

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
    
    conn = get_db_connection()
    events = conn.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 50").fetchall()
    conn.close()
    
    events_list = [dict(row) for row in events]
    
    return jsonify({
        'status': 'success',
        'total_returned': len(events_list),
        'data': events_list
    })

if __name__ == '__main__':
    app.run(debug=True)