from flask_app import app
from flask import render_template, request, redirect, session, flash
from flask_app.models.user import User
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)
dateFormat = "%#m/%#d/%Y %I:%M %p"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods =['POST'])
def reg():
    if User.validate_user(request.form):
        hashed_pass = bcrypt.generate_password_hash(request.form['password'])
        data = {
            'first_name' : request.form['first_name'],
            'last_name' : request.form['last_name'],
            'email' : request.form['email'],
            'password' : hashed_pass
        }
        user_id = User.save(data)
        print(f"user_id reg func ==> {user_id}")
        session["user_id"] = user_id
        return redirect('/dashboard')
    flash("Invalid Email", 'regError')
    return redirect('/')

@app.route('/login', methods = ['POST'])
def login():
    this_user = User.get_by_email(request.form)
    if this_user:
        if bcrypt.check_password_hash(this_user.password, request.form['password']):
            session["user_id"] = this_user.id
            return redirect('/dashboard')
    flash("Invalid Email", 'logError')
    return redirect('/')

@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return render_template("dashboard.html", user=User.get_by_id({'id': session['user_id']}))
    return redirect('/logout')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')