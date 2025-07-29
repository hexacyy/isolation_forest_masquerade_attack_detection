from flask import Blueprint, request, render_template, session, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from config import DB_FILE
from utils import is_strong_password, login_required

# Remove url_prefix to make routes accessible directly
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form['username']
        passwd = request.form['password']
        
        # DB lookup
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT password_hash, role FROM users WHERE username = ?", (uname,))
        result = c.fetchone()
        conn.close()
        
        if result and check_password_hash(result[0], passwd):
            session['username'] = uname
            session['role'] = result[1]
            flash("✅ Login successful.", "success")
            return redirect(url_for('dashboard.dashboard'))
        else:
            flash("❌ Invalid username or password.", "danger")
    
    return render_template("login.html")

@auth_bp.route('/logout')
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        uname = request.form['username']
        passwd = request.form['password']
        role = 'viewer'  # Always register as viewer for security
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (
                uname, generate_password_hash(passwd), role))
            conn.commit()
            flash("✅ Registration successful. You can now log in.", "success")
            return redirect(url_for('auth.login'))
        except sqlite3.IntegrityError:
            flash("❌ Username already exists.", "danger")
        finally:
            conn.close()
    
    return render_template("register.html")