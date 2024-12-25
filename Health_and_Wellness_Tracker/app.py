from random import randint
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL Configurationa
app.config['MYSQL_HOST'] = 'localhost'  
app.config['MYSQL_USER'] = 'root'       
app.config['MYSQL_PASSWORD'] = ''       
app.config['MYSQL_DB'] = 'wellness_program'  

# Initialize MySQL
mysql = MySQL(app)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        birthdate = request.form.get('birthdate')
        address = request.form.get('address')
        contact_number = request.form.get('contact_number')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Input validation
        if not username or not email or not password:
            flash('Please fill out all required fields.', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            flash('Invalid username. Only letters, numbers, dots, underscores, and hyphens are allowed.', 'danger')
            return redirect(url_for('register'))
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email address.', 'danger')
            return redirect(url_for('register'))
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('register'))

        # Hash the password securely
        hashed_password = generate_password_hash(password)

        # Save to database
        cur = mysql.connection.cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, first_name, last_name, birthdate, address, contact_number, email, password, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, first_name, last_name, birthdate, address, contact_number, email, hashed_password, role))
            mysql.connection.commit()
            flash('Registration Successful!', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            mysql.connection.rollback()
            if "Duplicate" in str(e):  # Check for duplicate entry errors
                flash('Username or email already exists.', 'danger')
            else:
                flash('An error occurred during registration. Please try again.', 'danger')
            return redirect(url_for('register'))
        finally:
            cur.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Input validation
        if not username or not password:
            flash('Please fill out all required fields.', 'danger')
            return redirect(url_for('login'))

        # Check in the 'users' table (both user and admin)
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()

        if user and check_password_hash(user[8], password):  # Assuming password is the 8th column in 'users' table
            session['username'] = username
            session['role'] = user[9]  # Assuming role is the 9th column in 'users' table
            
            flash('Login Successful!', 'success')
            
            # Redirect based on user role
            if user[9] == 'admin':  # Admin role
                return redirect(url_for('admin_dashboard'))
            else:  # User role
                return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')
        
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'role' in session and session['role'] == 'admin':
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users")
        users = cur.fetchall()
        cur.close()

        # Pass the users data to the template
        return render_template('admin_dashboard.html', users=users)
    else:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/admin/create_user', methods=['GET', 'POST'])
def create_user():
    if 'role' not in session or session['role'] != 'admin':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        birthdate = request.form.get('birthdate')
        address = request.form.get('address')
        contact_number = request.form.get('contact_number')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')

        # Input validation
        if not username or not email or not password:
            flash('Please fill out all required fields.', 'danger')
            return redirect(url_for('create_user'))
        if not re.match(r'^[a-zA-Z0-9_.-]+$', username):
            flash('Invalid username. Only letters, numbers, dots, underscores, and hyphens are allowed.', 'danger')
            return redirect(url_for('create_user'))
        if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            flash('Invalid email address.', 'danger')
            return redirect(url_for('create_user'))
        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'danger')
            return redirect(url_for('create_user'))

        # Hash the password securely
        hashed_password = generate_password_hash(password)

        # Save to database
        cur = mysql.connection.cursor()
        try:
            cur.execute("""
                INSERT INTO users (username, first_name, last_name, birthdate, address, contact_number, email, password, role)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (username, first_name, last_name, birthdate, address, contact_number, email, hashed_password, role))
            mysql.connection.commit()
            flash('User created successfully!', 'success')
            return redirect(url_for('admin_dashboard'))
        except Exception as e:
            mysql.connection.rollback()
            if "Duplicate" in str(e):
                flash('User already registered', 'danger')
            else:return redirect(url_for('create_user'))
        finally:
            cur.close()
            
    return render_template('create_user.html')

@app.route('/admin/delete_user/<int:id>')
def delete_user(id):
    if 'role' not in session or session['role'] != 'admin':
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor()
    
    try:
        # Retrieve the username associated with the user ID
        cur.execute("SELECT username FROM users WHERE id = %s", (id,))
        user = cur.fetchone()

        if user:
            username = user[0]

            # Delete related activities for this user
            cur.execute("DELETE FROM activities WHERE username = %s", (username,))

            # Delete the user
            cur.execute("DELETE FROM users WHERE id = %s", (id,))
            mysql.connection.commit()
            flash('User and related activities deleted successfully!', 'success')
        else:
            flash("User not found.", 'danger')

    except Exception as e:
        flash(f"Error: {e}", 'danger')
    
    finally:
        cur.close()

    return redirect(url_for('admin_dashboard'))

@app.route('/admin/logout')
def admin_logout():
    # Check if the user is an admin before logging out
    if 'role' in session and session['role'] == 'admin':
        session.clear()  # Clear the session
        flash('You have been logged out as admin.', 'info')
        return redirect(url_for('login'))  # Redirect to login page
    else:
        flash('You are not logged in as admin.', 'danger')
        return redirect(url_for('home'))  # Redirect to home if not admin

@app.route('/user/dashboard')
def user_dashboard():
    if 'role' in session and session['role'] == 'user':
        username = session['username']
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        cur.close()
        
        return render_template('user_dashboard.html', user=user)
    else:
        flash('You do not have permission to view this page.', 'danger')
        return redirect(url_for('login'))

@app.route('/user/edit_profile', methods=['GET', 'POST']) 
def user_edit_profile():
    if 'username' not in session or session['role'] != 'user':
        flash('Access denied. User only', 'danger')
        return redirect(url_for('login'))
    
    username = session['username']
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cur.fetchone()

    if request.method == 'POST':
        if 'change_password' in request.form:
            return redirect(url_for('set_new_password'))

        # Get form data
        new_username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        birthdate = request.form.get('birthdate')
        address = request.form.get('address')
        contact_number = request.form.get('contact_number')
        email = request.form.get('email')

        # Update profile if any field has changed
        cur.execute(""" 
            UPDATE users
            SET first_name = %s, last_name = %s, birthdate = %s, address = %s, contact_number = %s, email = %s
            WHERE username = %s
        """, (first_name, last_name, birthdate, address, contact_number, email, username))
        
        # Commit changes to the database
        mysql.connection.commit()
        
        # Check if the username was changed, and if so, update the session
        if new_username and new_username != username:
            session['username'] = new_username  # Update session with the new username
            
        cur.close()

        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_dashboard'))

    return render_template('user_edit_profile.html', user=user)

@app.route('/user/set_new_password', methods=['GET', 'POST'])
def set_new_password():
    if 'username' not in session or session['role'] != 'user':
        flash('Access denied. User only', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # Check if current password matches the one stored in the database
        username = session['username']
        cur = mysql.connection.cursor()
        cur.execute("SELECT password FROM users WHERE username = %s", (username,))
        stored_password = cur.fetchone()
        cur.close()

        if not stored_password or not check_password_hash(stored_password[0], current_password):
            flash('Current password is incorrect. Please try again.', 'danger')
            return redirect(url_for('set_new_password'))

        # Validate the new password and confirmation match
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return redirect(url_for('set_new_password'))

        # Hash the new password and update it in the database
        hashed_password = generate_password_hash(new_password)
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE users
            SET password = %s
            WHERE username = %s
        """, (hashed_password, username))
        mysql.connection.commit()
        cur.close()

        # Log out the user by clearing the session
        session.clear()

        flash('Password updated successfully! Please log in again.', 'success')
        return redirect(url_for('login'))

    return render_template('set_new_password.html')

@app.route('/user/set_activity', methods=['GET', 'POST'])
def set_activity():
    if 'username' not in session or session['role'] != 'user':
        flash('Access denied. User only', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        activity_name = request.form.get('activity_name')
        activity_type = request.form.get('activity_type')
        description = request.form.get('description')
        date = request.form.get('date')
        time = request.form.get('time')

        # Check if time is provided
        if not time:
            flash('Time cannot be empty', 'danger')
            return redirect(url_for('set_activity'))

        # Determine activity type and initialize relevant counter
        if activity_type == 'walking':
            counter_type = 'steps'
            counter_description = 'steps counter'
        elif activity_type == 'running':
            counter_type = 'km'
            counter_description = 'km counter'
        elif activity_type == 'cycling':
            counter_type = 'km'
            counter_description = 'cycling distance counter'
        elif activity_type == 'meditation':
            counter_type = 'minutes'
            counter_description = 'meditation time counter'
        else:
            flash('Invalid activity type selected.', 'danger')
            return redirect(url_for('set_activity'))

        # Save the activity and its specific counter to the database
        cur = mysql.connection.cursor()
        cur.execute(""" 
            INSERT INTO activities (activity_name, activity_type, description, date, time, username, counter_type, counter_description)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """, (activity_name, activity_type, description, date, time, session['username'], counter_type, counter_description))

        mysql.connection.commit()
        cur.close()
        
        flash('Activity set successfully!', 'success')
        return redirect(url_for('user_dashboard'))
    
    return render_template('set_activity.html')

@app.route('/user/view_activity', methods=['GET'])
def view_activity():
    # Fetch all activities for the current user
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM activities WHERE username = %s", [session['username']])
    activities = cur.fetchall()
    cur.close()
    
    # Render the activities page
    return render_template('view_activity.html', activities=activities)

@app.route('/user/logout')
def user_logout():
    # Check if the user is logged in
    if 'username' in session and session['role'] == 'user':
        session.clear()  # Clear the session to log out
        flash('You have been logged out successfully.', 'info')
        return redirect(url_for('login'))  # Redirect to login page after logout
    else:
        flash('You are not logged in.', 'danger')
        return redirect(url_for('home'))  # Redirect to home page if not logged in

if __name__ == '__main__':
    app.run(debug=True)
    