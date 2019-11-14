from flask import Flask, render_template, request, flash, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_required, login_user, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

db = SQLAlchemy(app)
login_manager = LoginManager(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.secret_key = 'My secret'


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(50), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)

    def generate_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)


class Post(db.Model):
    __tablename__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.String, nullable=False)
    user_id = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(
        db.DateTime, server_default=db.func.now(), server_onupdate=db.func.now())


@login_manager.user_loader
def load_user(id):
    return User.query.get(id)


login_manager.login_view = 'login'


db.create_all()


@app.route('/')
@login_required
def root():
    # query posts from database
    posts = Post.query.all()
    # modify our posts so that each post will include all author info:
    for post in posts:
        post.author = User.query.filter_by(id=post.user_id).first()
    return render_template('views/index.html', posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('root'))
    # By default (GET REQUEST), python will skip this condition and just return render_template at the end of this function. But If the user submit the form, this line will be checked
    if request.method == 'POST':
        # we use the email that user provides and check if that email is taken or not
        check_email = User.query.filter_by(email=request.form['email']).first()
        if check_email:  # if email taken
            flash('Email already taken', 'warning')  # we alert the user
            # then reload the register page again
            return redirect(url_for('register'))
        # if email not taken, we add new user to the database
        # we start with create an object for new_user
        new_user = User(name=request.form['name'],
                        email=request.form['email'])
        # raw password will be hashed using the generate_password method
        new_user.generate_password(request.form['password'])
        db.session.add(new_user)  # then we add new user to our session
        db.session.commit()  # then we commit to our database (kind of like save to db)
        login_user(new_user)  # then we log this user into our system
        flash('Successfully create an account and logged in', 'success')
        return redirect(url_for('root'))  # and redirect user to our root
    return render_template('views/register.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('root'))
    if request.method == 'POST':
        user = User.query.filter_by(email=request.form['email']).first()
        if not user:
            flash('Email is not registered', 'warning')
            return redirect(url_for('register'))
        if user.check_password(request.form['password']):
            login_user(user)
            flash('Welcome back {current_user.name!}', 'success')
            return redirect(url_for('root'))
        flash('wrong password or email', 'warning')
        return redirect(url_for('login'))
    return render_template('views/login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/posts', methods=['POST'])
@login_required
def create_post():
    if request.method == 'POST':
        new_post = Post(body=request.form['body'],
                    user_id=current_user.id)
        db.session.add(new_post)
        db.session.commit()
    return redirect(url_for('root'))


@app.route('/posts/<id>', methods=['POST', 'GET'])
def single_post(id):
    action = request.args.get('action')
    print(action)
    post = Post.query.get(id)
    if not post:
        flash('Post not found', 'warning')
        return redirect(url_for('root'))
    post.author = User.query.get(post.user_id)
    if request.method == "POST":
        if post.user_id != current_user.id:
            flash('not allow to do this', 'danger')
            return redirect(url_for('root'))
        if action == 'delete':
            db.session.delete(post)
            db.session.commit()
            return redirect(url_for('root'))
        elif action == 'udpate':
            post.body = request.form['body']
            db.session.commit()
            return redirect(url_for('single_post', id=id))
        elif action == 'edit':
            return render_template('views/single_post.html', post=post, action=action)
    if not action:
        action = 'view'
    return render_template('views/single_post.html', post=post, action=action)


if __name__ == "__main__":
    app.run(debug=True)
