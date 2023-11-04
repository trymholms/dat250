"""Provides all forms used in the Social Insecurity application.

This file is used to define all forms used in the application.
It is imported by the app package.

Example:
    from flask import Flask
    from app.forms import LoginForm

    app = Flask(__name__)

    # Use the form
    form = LoginForm()
    if form.validate_on_submit() and form.login.submit.data:
        username = form.username.data
    """

from datetime import datetime
from flask import request, make_response
from typing import cast
from wtforms.validators import InputRequired, Length, EqualTo, DataRequired, Regexp
"""from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user"""
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    DateField,
    FileField,
    FormField,
    PasswordField,
    StringField,
    SubmitField,
    TextAreaField,
)


# Defines all forms in the application, these will be instantiated by the template,
# and the routes.py will read the values of the fields

# TODO: Add validation, maybe use wtforms.validators??

# TODO: There was some important security feature that wtforms provides, but I don't remember what; implement it


"""
login_manager = LoginManager()
login_manager.init_app(app)


def load_user(user_id):
    # Load the user from your database
    return User.query.get(int(user_id))
"""
class LoginForm(FlaskForm):
    """Provides the login form for the application."""

    username = StringField(label="Username", render_kw={"placeholder": "Username"})
    password = PasswordField(label="Password", render_kw={"placeholder": "Password"})
    remember_me = BooleanField(
        label="Remember me"
    )  # TODO: It would be nice to have this feature implemented, probably by using cookies
    submit = SubmitField(label="Sign In")

def remember_user(self):
    if self.remember_me.data:
        username = self.username.data
        response = make_response()
        response.set_cookie("remember_me", username, max_age=3600 * 24 * 30) 

def get_remembered_user():
        return request.cookies.get("remember_me", "")

class RegisterForm(FlaskForm):
    """Provides the registration form for the application."""

    first_name = StringField(label="First Name", render_kw={"placeholder": "First Name"},validators=[InputRequired()])
    last_name = StringField(label="Last Name", render_kw={"placeholder": "Last Name"},validators=[InputRequired()])
    username = StringField(label="Username", render_kw={"placeholder": "Username"},validators=[InputRequired(),Length(min=4,max=25)])
    password = PasswordField(label="Password", render_kw={"placeholder": "Password"},validators=[DataRequired(),EqualTo('confirm_password', message='Passwords must match'), Regexp(r'^(?=.*[A-Z])(?=.*\d)(?=.*[a-z]).{8,}$',
                message='Password must contain at least one uppercase letter, one digit, and be at least 8 characters long.')])
    confirm_password = PasswordField(label="Confirm Password", render_kw={"placeholder": "Confirm Password"})
    submit = SubmitField(label="Sign Up")


class IndexForm(FlaskForm):
    """Provides the composite form for the index page."""

    login = cast(LoginForm, FormField(LoginForm))
    register = cast(RegisterForm, FormField(RegisterForm))


class PostForm(FlaskForm):
    """Provides the post form for the application."""

    content = TextAreaField(label="New Post", render_kw={"placeholder": "What are you thinking about?"})
    image = FileField(label="Image")
    submit = SubmitField(label="Post")


class CommentsForm(FlaskForm):
    """Provides the comment form for the application."""

    comment = TextAreaField(label="New Comment", render_kw={"placeholder": "What do you have to say?"})
    submit = SubmitField(label="Comment")


class FriendsForm(FlaskForm):
    """Provides the friend form for the application."""

    username = StringField(label="Friend's username", render_kw={"placeholder": "Username"})
    submit = SubmitField(label="Add Friend")


class ProfileForm(FlaskForm):
    """Provides the profile form for the application."""

    education = StringField(label="Education", render_kw={"placeholder": "Highest education"})
    employment = StringField(label="Employment", render_kw={"placeholder": "Current employment"})
    music = StringField(label="Favorite song", render_kw={"placeholder": "Favorite song"})
    movie = StringField(label="Favorite movie", render_kw={"placeholder": "Favorite movie"})
    nationality = StringField(label="Nationality", render_kw={"placeholder": "Your nationality"})
    birthday = DateField(label="Birthday", default=datetime.now())
    submit = SubmitField(label="Update Profile")
