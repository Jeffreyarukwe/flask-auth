from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'dev'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

# Configure Flask-Login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(User, user_id)


# CREATE TABLE IN DB
#  Mixins are sometimes described as being "included" rather than "inherited".
# Mixins encourage code reuse and can be used to avoid the inheritance ambiguity that multiple inheritance can cause
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
 
 
with app.app_context():
    db.create_all()


@app.route('/')
def home():

    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(request.form.get('password'),
                                                          method='pbkdf2:sha256', salt_length=8)
        new_user = User(email=email,
                        password=hash_and_salted_password,
                        name=request.form.get('name')
                        )

        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to database.
        login_user(new_user)

        return redirect(url_for('secrets'))
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':

        email = request.form.get('email')
        password = request.form.get('password')

        user = db.session.execute(db.select(User).where(User.email == email)).scalar()

        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('You were successfully logged in')
            return redirect(url_for('secrets'))
        else:
            error = 'Invalid credentials'
    return render_template("login.html", error=error)


@app.route('/secrets')
@login_required
def secrets():
    name = current_user.name
    return render_template("secrets.html", name=name)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    directory = 'static'
    return send_from_directory(directory, path='files/cheat_sheet.pdf')


if __name__ == "__main__":
    app.run(debug=True)
