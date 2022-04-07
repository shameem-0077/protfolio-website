from flask import Flask, render_template, redirect, flash, url_for, abort, request
from flask_wtf import FlaskForm
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL
from flask_bootstrap import Bootstrap
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, login_user, UserMixin, current_user, logout_user, login_required
import smtplib
import os


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
Bootstrap(app)


app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL", 'sqlite:///blog.db') #'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let Me In!")

class CreateProjectForm(FlaskForm):
    title = StringField("Project Title", validators=[DataRequired()])
    img_url = StringField("project Image URL", validators=[DataRequired(), URL()])
    submit = SubmitField("Submit Project")

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String(100))

class Projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    img_url = db.Column(db.String, nullable=False)

# db.create_all()

# hash_password = generate_password_hash("s8h0a8m6e0e0m5", method='pbkdf2:sha256', salt_length=8)

# admin = User(
#     username="Shameem",
#     email="shameemoff52@gmail.com",
#     password=hash_password
# )
#
# db.session.add(admin)
# db.session.commit()

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    return render_template(template_name_or_list='index.html')


@app.route('/contact', methods=['POST', 'GET'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        message = request.form.get('message')

        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user="shameemtest03@gmail.com", password="8086005565")
            connection.sendmail(from_addr=email,
                                to_addrs="shameemtest03@gmail.com",
                                msg=f"Name:{name}\n\n\nfrom:{email}\n\nMessage:{message}")

    return render_template(template_name_or_list='contact.html')

@app.route('/projects')
def project():
    projects = Projects.query.all()
    if projects == 0:
        print('dfdfsa')
    return render_template(template_name_or_list='project.html', projects=projects, current_user=current_user)

@app.route('/music')
def music():
    return render_template('music.html')

@app.route('/admin', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('project'))
    return render_template('login.html', form=form, current_user=current_user)

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/new-project', methods=['GET','POST'])
@login_required
def add_new_project():
    form = CreateProjectForm()
    if form.validate_on_submit():
        title = form.title.data
        img_url = form.img_url.data

        new_project = Projects(
            title=title,
            img_url=img_url
        )

        db.session.add(new_project)
        db.session.commit()
        return redirect(url_for('project'))
    return render_template('make-project.html', form=form, current_user=current_user)


@app.route('/delete/<int:project_id>')
@login_required
def delete_project(project_id):
    project_to_delete =Projects.query.get(project_id)
    db.session.delete(project_to_delete)
    db.session.commit()
    return redirect(url_for('project'))


if __name__ == "__main__":
    app.run(debug=True)