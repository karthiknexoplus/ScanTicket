from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pytz
from datetime import datetime
import requests
import jsonify
from datetime import datetime, timedelta
from sqlalchemy import func
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parking.db'
db = SQLAlchemy(app)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(10), nullable=False)  
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
class Ticket(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ticket_number = db.Column(db.String(20), nullable=False)
    device_id = db.Column(db.String(20), nullable=False)
    vehicle_type = db.Column(db.String(10), nullable=False)  
    timestamp = db.Column(db.DateTime, nullable=False)
    exit_timestamp = db.Column(db.DateTime, nullable=True)
    amount_paid = db.Column(db.Float, nullable=True)
    cashier_name = db.Column(db.String(80), nullable=True)
class Tariff(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    start_hour = db.Column(db.Integer, nullable=False)
    end_hour = db.Column(db.Integer, nullable=False)
    rate = db.Column(db.Float, nullable=False)
    vehicle_type = db.Column(db.String(2), nullable=False)
@app.route('/')
def index():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif user.role == 'cashier':
            return redirect(url_for('cashier_dashboard'))
    return redirect(url_for('login'))
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'cashier':
                return redirect(url_for('cashier_dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('role', None)
    return redirect(url_for('login'))
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(username=username, password=hashed_password, role=role)
        db.session.add(new_user)
        db.session.commit()
        flash('User created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')
from datetime import datetime, timedelta
from datetime import datetime, timedelta
from sqlalchemy import func
@app.route('/admin')
def admin_dashboard():
    if session.get('role') != 'admin':
        flash('Access denied', 'danger')
        return redirect(url_for('login'))
    users = User.query.all()
    tickets = Ticket.query.all()
    user_summaries = db.session.query(
        User.username,
        func.count(Ticket.id).label('total_tickets'),
        func.sum(Ticket.amount_paid).label('total_amount')
    ).join(Ticket, User.id == Ticket.cashier_name, isouter=True).group_by(User.id).all()
    today = datetime.now().date()
    last_day = today - timedelta(days=1)
    last_7_days = [today - timedelta(days=i) for i in range(7)]
    cashier_reports_today = db.session.query(
        Ticket.cashier_name,
        func.sum(Ticket.amount_paid).label('total_amount')
    ).filter(func.date(Ticket.timestamp) == today).group_by(Ticket.cashier_name).all()
    cashier_reports_last_day = db.session.query(
        Ticket.cashier_name,
        func.sum(Ticket.amount_paid).label('total_amount')
    ).filter(func.date(Ticket.timestamp) == last_day).group_by(Ticket.cashier_name).all()
    cashier_reports_last_7_days = []
    for date in last_7_days:
        daily_reports = db.session.query(
            Ticket.cashier_name,
            func.sum(Ticket.amount_paid).label('total_amount')
        ).filter(func.date(Ticket.timestamp) == date).group_by(Ticket.cashier_name).all()
        for report in daily_reports:
            cashier_reports_last_7_days.append({
                'date': date.strftime('%A, %Y-%m-%d'),
                'cashier_name': report.cashier_name,
                'total_amount': report.total_amount
            })
    return render_template('admin_dashboard.html', users=users, tickets=tickets,
                           user_summaries=user_summaries,
                           cashier_reports_today=cashier_reports_today,
                           cashier_reports_last_day=cashier_reports_last_day,
                           cashier_reports_last_7_days=cashier_reports_last_7_days)
from flask import Flask, render_template, request, redirect, url_for, flash, session
@app.route('/cashier-dashboard', methods=['GET', 'POST'])
def cashier_dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    ticket_info = None
    if request.method == 'POST':
        ticket_number = request.form.get('ticket_number')
        if not ticket_number:
            flash('Ticket number is required', 'danger')
        else:
            response = get_ticket_info(ticket_number)
            if response[1] == 200:
                ticket_info = response[0]
                store_ticket_info(ticket_info, session['username'])
                flash('Ticket details retrieved successfully', 'success')
            else:
                flash(response[0].get('error', 'Unknown error occurred'), 'danger')
    return render_template('cashier_dashboard.html', ticket=ticket_info)
def store_ticket_info(ticket_data, cashier_name):
    ticket_number = ticket_data.get('ticket_number')
    amount_paid = ticket_data.get('amount_to_be_paid')
    exit_timestamp_str = ticket_data.get('exit_timestamp')
    timestamp_str = ticket_data.get('timestamp')
    try:
        exit_timestamp = datetime.strptime(exit_timestamp_str, '%Y-%m-%d %H:%M:%S')
        timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
    except ValueError as e:
        print(f'Error parsing date: {e}')
        return
    ticket = Ticket.query.filter_by(ticket_number=ticket_number).first()
    if ticket:
        ticket.exit_timestamp = exit_timestamp
        ticket.amount_paid = amount_paid
        ticket.cashier_name = cashier_name
        print(f'Updated existing ticket: {ticket_number}')
    else:
        new_ticket = Ticket(
            ticket_number=ticket_number,
            device_id='default_device',  
            vehicle_type='unknown',  
            timestamp=timestamp,
            exit_timestamp=exit_timestamp,
            amount_paid=amount_paid,
            cashier_name=cashier_name
        )
        db.session.add(new_ticket)
        print(f'Created new ticket: {ticket_number}')
    db.session.commit()
@app.route('/get-ticket-info', methods=['POST'])
def get_ticket_info(ticket_number=None):
    if not ticket_number:
        ticket_number = request.json.get('ticket_number')
    if not ticket_number:
        return jsonify({'error': 'Ticket number is required'}), 400
    url = 'http://192.168.1.3:5000/submit-exit'
    data = {'ticket_number': ticket_number}
    try:
        response = requests.post(url, json=data)
        if response.status_code == 200:
            ticket = response.json()
            print_receipt(ticket)
            print('Ticket retrieved:', ticket)  
            return ticket, 200
        else:
            return jsonify({'error': 'Failed to fetch ticket info'}), 500
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500
import win32print
import datetime
def print_receipt(ticket):
    print(f"Printing receipt for ticket number: {ticket['ticket_number']}")
    print(f"Entry timestamp: {ticket['timestamp']}")
    print(f"Exit timestamp: {ticket['exit_timestamp']}")
    print(f"Amount to be paid: {ticket['amount_to_be_paid']}")
    entry_timestamp = datetime.datetime.strptime(ticket['timestamp'], '%Y-%m-%d %H:%M:%S')
    exit_timestamp = datetime.datetime.strptime(ticket['exit_timestamp'], '%Y-%m-%d %H:%M:%S')
    duration = exit_timestamp - entry_timestamp
    days = duration.days
    hours = duration.seconds // 3600
    minutes = (duration.seconds // 60) % 60
    duration_str = f'{days} days, {hours} hours, {minutes} min'
    printer_name = win32print.GetDefaultPrinter()
    raw_data = ''
    raw_data += '\x1B\x40'  
    raw_data += '\x1B\x61\x01'  
    raw_data += '\x1B\x21\x30'  
    raw_data += 'Parking\n'  
    raw_data += 'Receipt\n'  
    raw_data += '\n'
    raw_data += '\x1B\x21\x00'  
    raw_data += f'Ticket Number: {ticket["ticket_number"]}\n'  
    raw_data += f'Entry: {entry_timestamp.strftime("%Y-%m-%d %H:%M")}\n'  
    raw_data += f'Exit: {exit_timestamp.strftime("%Y-%m-%d %H:%M")}\n'  
    raw_data += f'Duration: {duration_str}\n'  
    raw_data += f'Amount to be paid: {ticket["amount_to_be_paid"]}\n'  
    raw_data += '\x1B\x61\x01'  
    raw_data += '----------------\n'  
    raw_data += 'Thank you for your visit!\n'  
    raw_data += 'Visit again!\n'  
    raw_data += 'Have a good day!\n'  
    raw_data += '\n'  
    raw_data += '\x1D\x56\x42\x00'  
    raw_data = raw_data.encode('utf-8')  
    printer_handle = win32print.OpenPrinter(printer_name)
    try:
        hJob = win32print.StartDocPrinter(printer_handle, 1, ('Receipt', None, 'RAW'))
        win32print.StartPagePrinter(printer_handle)
        win32print.WritePrinter(printer_handle, raw_data)
        win32print.EndPagePrinter(printer_handle)
    finally:
        win32print.EndDocPrinter(printer_handle)
        win32print.ClosePrinter(printer_handle)
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        app.run(host='0.0.0.0', port=8080)