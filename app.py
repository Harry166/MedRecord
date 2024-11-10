from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", "default_fallback_key")
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Define the root URL route
@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return redirect(url_for('register'))

# User database model
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

# Health record model
class HealthRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Registration route
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = bcrypt.generate_password_hash(request.form.get('password')).decode('utf-8')
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash('Account created! You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

# Login route
@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('You have been logged in!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login unsuccessful. Check email and password.', 'danger')
    return render_template('login.html')

# Logout route
@app.route("/logout", methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

# Home route (dashboard)
@app.route("/home", methods=['GET', 'POST'])
@login_required
def home():
    # Handle search query if present
    search_query = request.args.get('search', '')
    if search_query:
        records = HealthRecord.query.filter(
            (HealthRecord.title.ilike(f"%{search_query}%")) |
            (HealthRecord.content.ilike(f"%{search_query}%"))
        ).filter_by(user_id=current_user.id).all()
    else:
        records = HealthRecord.query.filter_by(user_id=current_user.id).all()
    
    return render_template('home.html', records=records, search_query=search_query)

# Route for adding health records
@app.route("/add_record", methods=['GET', 'POST'])
@login_required
def add_record():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        record = HealthRecord(title=title, content=content, user_id=current_user.id)
        db.session.add(record)
        db.session.commit()
        flash('Record added!', 'success')
        return redirect(url_for('home'))
    return render_template('add_record.html')

# Route for deleting health records
@app.route("/delete_record/<int:record_id>", methods=['POST'])
@login_required
def delete_record(record_id):
    record = HealthRecord.query.get_or_404(record_id)
    if record.user_id == current_user.id:
        db.session.delete(record)
        db.session.commit()
        flash('Record deleted!', 'success')
    else:
        flash('Unauthorized action.', 'danger')
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)