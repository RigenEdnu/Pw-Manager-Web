from flask import Flask, render_template, request, redirect, url_for, flash, session
from functools import wraps
import json
import random
import string
import os
from datetime import datetime
import hashlib

app = Flask(__name__, static_folder='public', template_folder='templates')
app.secret_key = os.urandom(24)

# JSON file path
JSON_FILE = 'database/password.json'

def load_passwd():
    with open(JSON_FILE, 'r') as f:
        return json.load(f)['passwords']

def reorder_ids_by_owner(data):
    """Reorder IDs for each owner starting from 1"""
    # Group passwords by owner
    passwords_by_owner = {}
    for item in data:
        owner = item.get('owner')
        if owner not in passwords_by_owner:
            passwords_by_owner[owner] = []
        passwords_by_owner[owner].append(item)
    
    # Reorder IDs for each owner's passwords
    reordered_data = []
    for owner, passwords in passwords_by_owner.items():
        for index, item in enumerate(passwords, start=1):
            item['id_pass'] = index
            reordered_data.append(item)
    
    return reordered_data

def save_passwd(data):
    # Reorder IDs before saving
    ordered_data = reorder_ids_by_owner(data)
    with open(JSON_FILE, 'w') as f:
        json.dump({'passwords': ordered_data}, f, indent=4)

# Ensure auth.json exists
def ensure_auth_file():
    if not os.path.exists('database/auth.json'):
        os.makedirs('database', exist_ok=True)
        save_users([])

# Updated login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            next_url = request.url if request.endpoint != 'login' else None
            if (next_url):
                session['next_url'] = next_url
            flash('Please login first!', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def load_users():
    ensure_auth_file()
    try:
        with open('database/auth.json', 'r') as f:
            return json.load(f).get('users', [])
    except:
        return []

def save_users(users):
    with open('database/auth.json', 'w') as f:
        json.dump({'users': users}, f, indent=4)

def save_login_history(username):
    try:
        history_file = 'database/login_history.json'
        if not os.path.exists(history_file):
            with open(history_file, 'w') as f:
                json.dump({'history': []}, f)
        
        with open(history_file, 'r') as f:
            data = json.load(f)
        
        login_entry = {
            'username': username,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        data['history'].append(login_entry)
        # Keep only last 5 entries
        data['history'] = data['history'][-5:]
        
        with open(history_file, 'w') as f:
            json.dump(data, f, indent=4)
    except Exception as e:
        print(f"Error saving login history: {str(e)}")

# Add template global context processor
@app.context_processor
def inject_login_history():
    return dict(login_history=get_login_history())

# Update the get_login_history function
def get_login_history():
    try:
        with open('database/login_history.json', 'r') as f:
            history = json.load(f)['history']
            # Reverse the order to show newest first
            return list(reversed(history))
    except:
        return []

def encrypt_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = encrypt_password(request.form.get('password'))  # Encrypt password
        
        if not username or not password:
            flash('Please fill all fields', 'danger')
            return render_template('auth/login.html')
        
        users = load_users()
        
        # Compare with encrypted password
        user = next((user for user in users 
                    if user['username'] == username
                    and user['password'] == password), None)
        
        if user:
            session['logged_in'] = True
            session['username'] = username
            save_login_history(username)
            flash('Login successful!', 'success')
            next_url = session.pop('next_url', None)
            return redirect(next_url or url_for('index'))
        
        flash('Invalid username or password', 'danger')
    
    return render_template('auth/login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            flash('Please fill all fields', 'danger')
            return render_template('auth/signup.html')
        
        if len(password) < 5:
            flash('Password must be at least 5 characters long', 'danger')
            return render_template('auth/signup.html')
        
        try:
            users = load_users()
            
            # Check if username exists using plain text comparison
            if any(user['username'] == username for user in users):
                flash('Username already exists', 'danger')
                return render_template('auth/signup.html')
            
            new_user = {
                'username': username,
                'password': encrypt_password(password)  # Encrypt password
            }
            
            users.append(new_user)
            save_users(users)
            flash('Registration successful! Please login', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            flash('Registration failed. Please try again.', 'danger')
            print(f"Registration error: {str(e)}")
            return render_template('auth/signup.html')
    
    return render_template('auth/signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))

def get_user_passwords(username):
    """Get passwords owned by specific user"""
    data = load_passwd()
    return [item for item in data if item.get('owner') == username]

@app.route('/')
@login_required
def index():
    user_passwords = get_user_passwords(session['username'])
    login_history = get_login_history()
    return render_template('home.html', 
                         data=user_passwords, 
                         total_passwords=len(user_passwords),
                         login_history=login_history)

@app.route('/management/password')
@login_required
def management_password():
    data = get_user_passwords(session['username'])
    for item in data:
        item['display_password'] = item['password']
    return render_template('management/index.html', data=data)

@app.route('/management/password/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        data = load_passwd()
        username = request.form['username']
        password = request.form['pass']  # Store plain password
        
        # Get max ID for current user
        user_passwords = [p for p in data if p.get('owner') == session['username']]
        new_id = len(user_passwords) + 1
        
        new_entry = {
            "id_pass": new_id,
            "label": request.form['label'],
            "username": username,
            "password": password,  # No encryption
            "owner": session['username']
        }
        
        data.append(new_entry)
        save_passwd(data)  # This will reorder all IDs
        flash('Data added successfully!', 'success')
        return redirect(url_for('management_password'))
    return render_template('management/add.html')

@app.route('/management/password/<int:id>/edit', methods=['GET', 'POST'])
@login_required
def edit(id):
    data = load_passwd()
    item = next((item for item in data if item['id_pass'] == id), None)
    
    # Check if user owns this password
    if not item or item.get('owner') != session['username']:
        flash('Access denied!', 'danger')
        return redirect(url_for('management_password'))
    
    if request.method == 'POST':
        item['label'] = request.form['label']
        item['username'] = request.form['username']
        item['password'] = request.form['pass']  # Store plain password
        
        save_passwd(data)
        flash('Data updated successfully!', 'success')
        return redirect(url_for('management_password'))
    
    return render_template('management/edit.html', item=item)

@app.route('/management/password/<int:id>/delete')
@login_required
def delete(id):
    data = load_passwd()
    
    # Only delete if user owns the password
    item = next((item for item in data if item['id_pass'] == id 
                 and item.get('owner') == session['username']), None)
    if not item:
        flash('Access denied!', 'danger')
        return redirect(url_for('management_password'))
    
    # Remove the item
    data = [item for item in data if not (item['id_pass'] == id 
            and item.get('owner') == session['username'])]
    
    save_passwd(data)  # This will reorder all IDs
    flash('Data deleted successfully!', 'success')
    return redirect(url_for('management_password'))

@app.route('/generate/password')
@login_required
def generate_password():
    return render_template('generate/add.html')

@app.route('/generate/password/save', methods=['POST'])
@login_required
def save_generated():
    data = load_passwd()
    username = request.form['username']
    password = request.form['password']  # Store plain password
    
    # Get max ID for current user
    user_passwords = [p for p in data if p.get('owner') == session['username']]
    new_id = len(user_passwords) + 1
    
    new_entry = {
        "id_pass": new_id,
        "label": request.form['label'],
        "username": username,
        "password": password,  # No encryption
        "owner": session['username']
    }
    
    data.append(new_entry)
    save_passwd(data)  # This will reorder all IDs
    flash('Password saved successfully!', 'success')
    return redirect(url_for('management_password'))

@app.route('/generate/password/create', methods=['POST'])
@login_required
def create_password():
    try:
        length = int(request.form.get('length', 12))
        if length < 3:
            length = 3
        elif length > 128:
            length = 128

        chars = ''
        if 'uppercase' in request.form:
            chars += string.ascii_uppercase
        if 'lowercase' in request.form:
            chars += string.ascii_lowercase
        if 'numbers' in request.form:
            chars += string.digits
        if 'symbols' in request.form:
            chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not chars:
            flash('Please select at least one character type', 'danger')
            return redirect(url_for('generate_password'))

        password = ''.join(random.choice(chars) for _ in range(length))
        # Pass the form data back to maintain state
        return render_template('generate/add.html', 
                             generated_password=password,
                             form=request.form)

    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
        return redirect(url_for('generate_password'))

if __name__ == '__main__':
    app.run(debug=True)
