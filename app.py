from flask import *
import json

app = Flask(__name__, static_folder='public', template_folder='templates')
app.secret_key = 'your-secret-key'

# JSON file path
JSON_FILE = 'database/password.json'

def load_passwd():
    with open(JSON_FILE, 'r') as f:
        return json.load(f)['passwords']

def save_passwd(data):
    with open(JSON_FILE, 'w') as f:
        json.dump({'passwords': data}, f, indent=4)

@app.route('/login')
def login():
    return render_template('auth/login.html')

@app.route('/signup')
def signup():
    return render_template('auth/signup.html')

@app.route('/')
def index():
    data = load_passwd()
    return render_template('home.html', data=data)

@app.route('/management/password')
def management_password():
    data = load_passwd()
    return render_template('management/index.html', data=data)

@app.route('/management/password/add', methods=['GET', 'POST'])
def add():
    if request.method == 'POST':
        data = load_passwd()
        new_entry = {
            "id_pass": len(data) + 1,  # This will always be correct now
            "label": request.form['label'],
            "username": request.form['username'],
            "password": request.form['pass']
        }
        data.append(new_entry)
        save_passwd(data)
        flash('Password added successfully!', 'success')
        return redirect(url_for('management_password'))
    return render_template('management/add.html')

@app.route('/management/password/<int:id>/edit', methods=['GET', 'POST'])
def edit(id):
    data = load_passwd()
    item = next((item for item in data if item['id_pass'] == id), None)
    
    if request.method == 'POST':
        item['label'] = request.form['label']
        item['username'] = request.form['username']
        item['password'] = request.form['pass']
        save_passwd(data)
        flash('Data updated successfully!', 'success')
        return redirect(url_for('management_password'))
    
    return render_template('management/edit.html', item=item)

@app.route('/management/password/<int:id>/delete')
def delete(id):
    data = load_passwd()
    # Remove the item with the specified id
    data = [item for item in data if item['id_pass'] != id]
    
    # Reorder the IDs sequentially
    for index, item in enumerate(data, start=1):
        item['id_pass'] = index
        
    save_passwd(data)
    flash('Data deleted successfully!', 'success')
    return redirect(url_for('management_password'))

@app.route('/generate/password')
def generate_password():
    return render_template('generate/add.html')

@app.route('/generate/password/save', methods=['POST'])
def save_generated():
    data = load_passwd()
    new_entry = {
        "id_pass": len(data) + 1,  # This will always be correct now
        "label": request.form['label'],
        "username": request.form['username'],
        "password": request.form['password']
    }
    data.append(new_entry)
    save_passwd(data)
    flash('Password saved successfully!', 'success')
    return redirect(url_for('management_password'))

if __name__ == '__main__':
    app.run(debug=True)
