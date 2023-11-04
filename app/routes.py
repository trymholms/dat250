"""Provides all routes for the Social Insecurity application.

This file contains the routes for the application. It is imported by the app package.
It also contains the SQL queries used for communicating with the database.
"""

from pathlib import Path
#import os
from flask import flash, redirect, render_template, send_from_directory, url_for, session
#from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from app.forms import CommentsForm, FriendsForm, IndexForm, PostForm, ProfileForm
#from app.database import SQLite3
#from werkzeug.utils import secure_filename
import time
from functools import wraps

import re
from app import app, sqlite

#db = SQLite3(app)

def escape(t):
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;").replace('"', "&quot;")
    return t

def allowed_file(filename):
    allowed_extensions = app.config.get('ALLOWED_EXTENSIONS', [])
    if not allowed_extensions:
        return False
    file_extension = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    return file_extension in allowed_extensions

def check_failed_attempts(username):
    if username in failed_login_attempts:
        attempts, last_attempt_time = failed_login_attempts[username]
        lockout_duration = 300  # Lockout duration in seconds

        if attempts >= 3 and (time.time() - last_attempt_time) < lockout_duration:
            flash("Account temporarily locked due to multiple failed login attempts. Try again later.", category="danger")
            return True

    return False


def sanitize_input(input_str, field):
    # Remove characters that are not allowed in usernames and names
    sanitized_str = re.sub(r"[^a-zA-Z0-9@!$%*?&\s]", "", input_str)

    # Check if any characters were removed and inform the user
    if sanitized_str != input_str:
        flash(f"Some characters in your input were removed due to invalid characters in {field}.", category="warning")
        return False 
    return sanitized_str

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session or session['username'] != kwargs.get('username'):
            flash("You are not authorized to access this page.", category="danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated_function

failed_login_attempts = {}

@app.route("/", methods=["GET", "POST"])
@app.route("/index", methods=["GET", "POST"])
def index():
    index_form = IndexForm()
    login_form = index_form.login
    register_form = index_form.register

    if login_form.is_submitted() and login_form.submit.data:
        username = login_form.username.data

        if check_failed_attempts(username):
            return render_template("index.html.j2", title="Welcome", form=index_form)

    
        user = sqlite.select_user_by_username(username)
        

        if user is None:
            flash("Sorry, this user does not exist!", category="warning")
        elif not check_password_hash(user["password"], login_form.password.data):
            flash("Sorry, wrong password!", category="warning")
        else:
            session['username'] = username
            return redirect(url_for("stream", username=session['username']))

        return render_template("index.html.j2", title="Welcome", form=index_form)

    elif register_form.is_submitted() and register_form.submit.data:
        # Check if the password meets the strong password 
        strong_password_pattern = r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$"
        if not re.match(strong_password_pattern, register_form.password.data):
            flash("Password does not meet the strong password criteria. It should contain at least one uppercase letter, one lowercase letter, one digit, one special character (@, $, !, %, *, ?, or &), and be at least 8 characters long.", category="danger")
            return render_template("index.html.j2", title="Welcome", form=index_form)

        # Sanitize user input
        hashed_password = generate_password_hash(register_form.password.data)
        
        sanitized_username = sanitize_input(register_form.username.data, 'username')
        sanitized_first_name = sanitize_input(register_form.first_name.data, 'first name')
        sanitized_last_name = sanitize_input(register_form.last_name.data, 'last name')
        
        if sanitized_username is False or sanitized_first_name is False or sanitized_last_name is False:
            flash("User registration failed due to invalid input.", category="danger")
            return render_template("index.html.j2", title="Welcome", form=index_form)

        sqlite.register_user(sanitized_username,sanitized_first_name, sanitized_last_name, hashed_password)

        flash("User successfully created!", category="success")
        return redirect(url_for("index"))


    return render_template("index.html.j2", title="Welcome", form=index_form)

@app.route("/stream/<string:username>", methods=["GET", "POST"])
@login_required
def stream(username: str):
    if 'username' in session:
        """Provides the stream page for the application.

        If a form was submitted, it reads the form data and inserts a new post into the database.

        Otherwise, it reads the username from the URL and displays all posts from the user and their friends.
        """
        post_form = PostForm()
        get_user = f"""
            SELECT *
            FROM Users
            WHERE username = '{username}';
            """
        user = sqlite.query(get_user, one=True)

        if post_form.is_submitted():
            if post_form.image.data:
                path = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"] / post_form.image.data.filename
                post_form.image.data.save(path)

            sanitizzed_content = sanitize_input(post_form.content.data, "posting")

            sqlite.insert_post(user["id"], sanitizzed_content, post_form.image.data.filename)

            return redirect(url_for("stream", username=session['username']))

        get_posts = f"""
            SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id = p.id) AS cc
            FROM Posts AS p JOIN Users AS u ON u.id = p.u_id
            WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id = {user["id"]}) OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id = {user["id"]}) OR p.u_id = {user["id"]}
            ORDER BY p.creation_time DESC;
            """
        posts = sqlite.query(get_posts)
        return render_template("stream.html.j2", title="Stream", username=session['username'], form=post_form, posts=posts)
    
@app.route("/comments/<string:username>/<int:post_id>", methods=["GET", "POST"])
@login_required
def comments(username: str, post_id: int):
    comments_form = CommentsForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if comments_form.is_submitted():
        sqlite.insert_comment(post_id, user["id"], comments_form.comment.data)

    get_post = f"""
        SELECT *
        FROM Posts AS p JOIN Users AS u ON p.u_id = u.id
        WHERE p.id = {post_id};
        """
    get_comments = f"""
        SELECT DISTINCT *
        FROM Comments AS c JOIN Users AS u ON c.u_id = u.id
        WHERE c.p_id={post_id}
        ORDER BY c.creation_time DESC;
        """
    post = sqlite.query(get_post, one=True)
    comments = sqlite.query(get_comments)
    return render_template(
        "comments.html.j2", title="Comments", username=username, form=comments_form, post=post, comments=comments
    )

@app.route("/friends/<string:username>", methods=["GET", "POST"])
def friends(username: str):
    """Provides the friends page for the application.

    If a form was submitted, it reads the form data and inserts a new friend into the database.

    Otherwise, it reads the username from the URL and displays all friends of the user.
    """
    friends_form = FriendsForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if friends_form.is_submitted():
        get_friend = f"""
            SELECT *
            FROM Users
            WHERE username = '{friends_form.username.data}';
            """
        friend = sqlite.query(get_friend, one=True)
        get_friends = f"""
            SELECT f_id
            FROM Friends
            WHERE u_id = {user["id"]};
            """
        friends = sqlite.query(get_friends)

        if friend is None:
            flash("User does not exist!", category="warning")
        elif friend["id"] == user["id"]:
            flash("You cannot be friends with yourself!", category="warning")
        elif friend["id"] in [friend["f_id"] for friend in friends]:
            flash("You are already friends with this user!", category="warning")
        else:
            insert_friend = f"""
                INSERT INTO Friends (u_id, f_id)
                VALUES ({user["id"]}, {friend["id"]});
                """
            sqlite.query(insert_friend)
            flash("Friend successfully added!", category="success")

    get_friends = f"""
        SELECT *
        FROM Friends AS f JOIN Users as u ON f.f_id = u.id
        WHERE f.u_id = {user["id"]} AND f.f_id != {user["id"]};
        """
    friends = sqlite.query(get_friends)
    return render_template("friends.html.j2", title="Friends", username=username, friends=friends, form=friends_form)


@app.route("/profile/<string:username>", methods=["GET", "POST"])
def profile(username: str):
    """Provides the profile page for the application.

    If a form was submitted, it reads the form data and updates the user's profile in the database.

    Otherwise, it reads the username from the URL and displays the user's profile.
    """
    profile_form = ProfileForm()
    get_user = f"""
        SELECT *
        FROM Users
        WHERE username = '{username}';
        """
    user = sqlite.query(get_user, one=True)

    if profile_form.is_submitted():
        update_profile = f"""
            UPDATE Users
            SET education='{profile_form.education.data}', employment='{profile_form.employment.data}',
                music='{profile_form.music.data}', movie='{profile_form.movie.data}',
                nationality='{profile_form.nationality.data}', birthday='{profile_form.birthday.data}'
            WHERE username='{username}';
            """
        sqlite.query(update_profile)
        return redirect(url_for("profile", username=username))

    return render_template("profile.html.j2", title="Profile", username=username, user=user, form=profile_form)



@app.route("/uploads/<string:filename>", endpoint="uploads")
def uploads(filename):
    """Provides an endpoint for serving uploaded files."""
    return send_from_directory(Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"], filename)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if 'username' in session:
        # Clear the user's session data to log them out
        session.pop('username', None)
        flash("You have been logged out successfully.", category="success")
    else:
        flash("You were never logged in...", category="danger")

    return redirect(url_for('index'))