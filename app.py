import time
from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash
from datetime import datetime
import re
from flask_restful import Resource, Api
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
api = Api(app)

# Postgres stuff
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:sql1234@localhost:5432/flaskdb"
SQLALCHEMY_TRACK_MODIFICATIONS = False

db = SQLAlchemy(app)
bcrypt = Bcrypt()


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    firstname = db.Column(db.String(50), nullable=False)
    middlename = db.Column(db.String(50))
    lastname = db.Column(db.String(50), nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)


class OnlineUser(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    ipaddress = db.Column(db.String(45), nullable=False)
    logindatetime = db.Column(db.DateTime, default=datetime.utcnow)


def log(text):
    logtime = datetime.now()
    logtime = (logtime.strftime("%c"))
    with open('logs/log.txt', 'a') as file:
        file.write(logtime + '\t:\t' + text + '\n')


@app.route('/')
def index():  # put application's code here
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(data.get('password')):
            # Check if user is already in the OnlineUser table
            existing_online_user = OnlineUser.query.filter_by(username=user.username).first()
            if not existing_online_user:
                online_user = OnlineUser(username=user.username, ipaddress=request.remote_addr)
                db.session.add(online_user)
                db.session.commit()

            session['username'] = user.username
            flash('Login successful', 'success')

            # Log successful login
            log(f"User '{username}' logged in successfully from IP: {request.remote_addr}")

            return redirect(url_for('user_list'))
        else:
            flash('Invalid credentials', 'danger')

            # Log failed login attempt
            log(f"Failed login attempt for user '{username}' from IP: {request.remote_addr}")

            return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
def logout():
    if 'username' in session:
        username = session['username']
        # Remove user from OnlineUser table
        online_user = OnlineUser.query.filter_by(username=session['username']).first()
        if online_user:
            db.session.delete(online_user)
            db.session.commit()

        log(f"User '{username}' logged out,  from IP: {request.remote_addr}")

        session.pop('username', None)
        flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# Utility function to validate email
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)


def is_valid_password(password):
    # Password must be at least 8 characters long, include one uppercase letter,
    # one number, and one special character.
    password_regex = re.compile(
        r'^(?=.*[A-Z])(?=.*\d)(?=.*[@#$%^&+=])(?=.*[a-zA-Z]).{8,}$'
    )
    return re.match(password_regex, password) is not None


@app.route('/user/create', methods=['GET', 'POST'])
def user_create():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        firstname = request.form.get('firstname')
        middlename = request.form.get('middlename')
        lastname = request.form.get('lastname')
        birthdate = request.form.get('birthdate')

        email_regex = re.compile(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$')
        password_regex = re.compile(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=]).{8,}$')

        # Check if the username already exists
        if User.query.filter_by(username=username).first():
            flash(f"Username '{username}' already exists.")
            return render_template('user_create.html', username=username, email=email,
                                   firstname=firstname, middlename=middlename,
                                   lastname=lastname, birthdate=birthdate)

        if User.query.filter_by(email=email).first():
            flash(f"Email '{email}' already exists.")
            return render_template('user_create.html', username=username, email=email,
                                   firstname=firstname, middlename=middlename,
                                   lastname=lastname, birthdate=birthdate)

        if len(username) < 6:
            flash('Username must be at least 6 characters long.')
            return render_template('user_create.html', username=username, email=email,
                                   firstname=firstname, middlename=middlename,
                                   lastname=lastname, birthdate=birthdate)

        if not re.match(email_regex, email):
            flash(f'Invalid email format: {email}')
            return render_template('user_create.html', username=username, email=email,
                                   firstname=firstname, middlename=middlename,
                                   lastname=lastname, birthdate=birthdate)

        if not re.match(password_regex, password):
            flash('Password must be at least 8 characters long, include one uppercase letter, '
                  'one number, and one special character.')
            return render_template('user_create.html', username=username, email=email,
                                   firstname=firstname, middlename=middlename,
                                   lastname=lastname, birthdate=birthdate)

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(
            username=username,
            firstname=firstname,
            middlename=middlename,
            lastname=lastname,
            birthdate=birthdate,
            email=email,
            password_hash=password_hash
        )

        db.session.add(new_user)
        db.session.commit()

        log(f'New user created: {username}')

        flash('New user created successfully!')
        time.sleep(2)
        return redirect(url_for('login'))

    return render_template('user_create.html')


@app.route('/user/list', methods=['GET'])
def user_list():
    users = User.query.all()
    return render_template('user_list.html', users=users)


@app.route('/user/delete/<int:id>', methods=['GET', 'POST'])
def user_delete(id):
    # Check if user is logged in
    if 'username' not in session:
        flash('Please log in to perform this action', 'danger')
        return redirect(url_for('login'))

    logged_in_username = session.get('username')
    user_to_delete = User.query.filter_by(id=id).first()

    if not user_to_delete:
        flash('User not found', 'danger')
        return redirect(url_for('user_list'))

    if request.method == 'POST':
        # Remove the user from OnlineUser table
        online_user = OnlineUser.query.filter_by(username=user_to_delete.username).first()
        if online_user:
            db.session.delete(online_user)

    # Ensure the logged-in user can only delete their own account
    if user_to_delete.username != logged_in_username:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_list'))

    if request.method == 'POST':
        # Perform the deletion
        User.query.filter_by(id=id).delete()
        db.session.commit()
        log(f'User {logged_in_username} deleted')
        flash('Your account has been deleted successfully!', 'success')
        return redirect(url_for('login'))  # Redirect to login after deletion

    # Render the confirmation modal page
    return redirect(url_for('user_list'))  # Redirect to login after deletion


@app.route('/user/update/<int:id>', methods=['GET', 'POST'])
def user_update(id):
    if 'username' not in session:
        flash('Please log in to update your information', 'danger')
        return redirect(url_for('login'))

    logged_in_username = session.get('username')
    update_user = User.query.filter_by(id=id).first()

    if not update_user:
        flash('User not found', 'danger')
        return redirect(url_for('user_list'))

    if update_user.username != logged_in_username:
        flash('Unauthorized access', 'danger')
        return redirect(url_for('user_list'))

    if request.method == 'POST':
        output = []

        # Get the form data
        firstname = request.form.get('firstname')
        middlename = request.form.get('middlename')
        lastname = request.form.get('lastname')
        birthdate_str = request.form.get('birthdate')  # Get the date string from form
        email = request.form.get('email')
        password = request.form.get('password')

        # Validate and update the email
        if email:
            if is_valid_email(email):
                existing_user = User.query.filter_by(email=email).first()
                if existing_user and existing_user.id != id:
                    flash('Email is already registered by another user', 'danger')
                    return render_template('user_update.html', user=update_user,
                                           firstname=firstname, middlename=middlename,
                                           lastname=lastname, birthdate=birthdate_str)
                if update_user.email != email:
                    update_user.email = email
                    output.append('Email updated')
            else:
                flash('Invalid email format', 'danger')
                return render_template('user_update.html', user=update_user,
                                       firstname=firstname, middlename=middlename,
                                       lastname=lastname, birthdate=birthdate_str)

        # Validate and update the password if provided
        if password:
            if is_valid_password(password):
                update_user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                output.append('Password updated')
            else:
                flash('Password must be at least 8 characters long, include one uppercase letter, '
                      'one number, and one special character.', 'danger')
                return render_template('user_update.html', user=update_user,
                                       firstname=firstname, middlename=middlename,
                                       lastname=lastname, birthdate=birthdate_str)

        # Convert form date string to a datetime.date object
        if birthdate_str:
            try:
                birthdate = datetime.strptime(birthdate_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid birthdate format', 'danger')
                return render_template('user_update.html', user=update_user,
                                       firstname=firstname, middlename=middlename,
                                       lastname=lastname, birthdate=birthdate_str)

            # Check if the birthdate has changed
            if update_user.birthdate != birthdate:
                update_user.birthdate = birthdate
                output.append('Birthdate updated')

        # Update other fields and check if they have changed
        if firstname and update_user.firstname != firstname:
            update_user.firstname = firstname
            output.append('First name updated')

        if middlename and update_user.middlename != middlename:
            update_user.middlename = middlename
            output.append('Middle name updated')

        if lastname and update_user.lastname != lastname:
            update_user.lastname = lastname
            output.append('Last name updated')

        # Commit the updates to the database
        db.session.commit()

        if output:
            log(f"User '{update_user.username}' updated: {', '.join(output)}")

        flash('User information updated successfully!', 'success')
        return redirect(url_for('user_update', id=id))

    return render_template('user_update.html', user=update_user)


@app.route('/onlineusers', methods=['GET'])
def online_users():
    if 'username' in session:
        # Query all online users from the OnlineUser model
        online_users = OnlineUser.query.all()

        # Format the results into a dictionary
        online_users_list = {user.id: {
            "username": user.username,
            "ipaddress": user.ipaddress,
            "logindatetime": user.logindatetime.strftime('%Y-%m-%d %H:%M:%S')
        } for user in online_users}

        # Log the event (optional)
        log("Online users listed")

        return jsonify(online_users_list)
    else:
        return jsonify({"error": "Login required"}), 403


# RESTful API Resources for Participants

class UserList(Resource):
    def get(self):
        users = User.query.all()
        return [
            {
                'username': user.username,
                'firstname': user.firstname,
                'middlename': user.middlename,
                'lastname': user.lastname,
                'email': user.email,
                'birthdate': user.birthdate.strftime('%Y-%m-%d'),  # Formatting birthdate as a string
                'password': user.password_hash  # Exposing the hashed password (not recommended in production)
            } for user in users
        ]

    def post(self):
        data = request.get_json()
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        firstname = data.get('firstname')
        middlename = data.get('middlename')
        lastname = data.get('lastname')
        birthdate = datetime.strptime(data.get('birthdate'), '%Y-%m-%d').date()

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            return {'message': 'User with this username or email already exists'}, 400

        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        new_user = User(
            username=username,
            firstname=firstname,
            middlename=middlename,
            lastname=lastname,
            birthdate=birthdate,
            email=email,
            password_hash=password_hash
        )

        db.session.add(new_user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201

    def put(self):
        data = request.json
        username = data.get('username')
        user = User.query.filter_by(username=username).first()

        if not user:
            return {'message': f"User '{username}' not found"}, 404

        # Update user's details
        user.firstname = data.get('firstname', user.firstname)
        user.middlename = data.get('middlename', user.middlename)
        user.lastname = data.get('lastname', user.lastname)
        user.email = data.get('email', user.email)

        birthdate_str = data.get('birthdate')
        if birthdate_str:
            try:
                user.birthdate = datetime.strptime(birthdate_str, '%Y-%m-%d').date()
            except ValueError:
                return {'message': 'Invalid date format'}, 400

        password = data.get('password')
        if password:
            user.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        db.session.commit()
        return {'message': f"User '{username}' updated successfully"}, 200

    def delete(self):
        data = request.json
        username = data.get('username')
        user = User.query.filter_by(username=username).first()

        if not user:
            return {'message': f"User '{username}' not found"}, 404

        # Remove user from the database
        db.session.delete(user)
        db.session.commit()

        return {'message': f"User '{username}' deleted successfully"}, 200


class OnlineUserList(Resource):
    def get(self):
        users = OnlineUser.query.all()
        return [
            {
                'username': user.username,
                'ipaddress': user.ipaddress,
                'logindatetime': user.logindatetime.strftime('%Y-%m-%d %H:%M:%S')
            } for user in users
        ]

    def delete(self):
        data = request.get_json()
        username = data.get('username')
        user = OnlineUser.query.filter_by(username=username).first()

        if not user:
            return {'message': 'Online user not found'}, 404

        db.session.delete(user)
        db.session.commit()
        return {'message': f'Online user {user.username} deleted successfully'}, 200


api.add_resource(UserList, '/api/user/create')
api.add_resource(OnlineUserList, '/api/onlineusers')

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.2', port=5000)
