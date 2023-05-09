from flask import Flask, render_template, redirect, url_for, flash,request,abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from sqlalchemy.ext.declarative import declarative_base

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)



##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)

Base = declarative_base()
gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False,
                    force_lower=False, use_ssl=False, base_url=None)

@login_manager.user_loader
def load_user(user_id):
    return BlogUser.query.get(int(user_id))


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # Create Foreign Key, "users.id" the users refers to the table name of User.
    author_id = db.Column(db.Integer, db.ForeignKey("blog_users.id"))
    # Create reference to the User object, the "posts" refers to the posts property in the User class.
    authors = relationship("BlogUser", back_populates="posts")


    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
with app.app_context():
    db.create_all()

class BlogUser(UserMixin, db.Model):
    __tablename__ = "blog_users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    email = db.Column(db.String(250),unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)

    # This will act like a List of BlogPost objects attached to each User.
    # The "author" refers to the author property in the BlogPost class.
    posts = relationship("BlogPost", back_populates="authors")

with app.app_context():
    db.create_all()

class UserComment (db.Model):
    __tablename__ = "user_comment"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    current_post = db.Column(db.Integer, nullable=False)
    # authors = relationship("BlogUser", back_populates="posts")
    comment= db.Column(db.Text, nullable=False)

with app.app_context():
    db.create_all()

#Create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        #If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        #Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def home():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)



@app.route('/all_posts')
@login_required
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=True, user=current_user)


@app.route('/register', methods=['GET','POST'])
def register():
    logout_user()
    form = RegisterForm()
    if request.method == "POST":

        if BlogUser.query.filter_by(email=request.form.get('email')).first():
            # User already exists
            flash("Email already exists! Log in instead!")
            return redirect(url_for('register'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=7
        )

        new_user= BlogUser(
            name=request.form.get("name"),
            email=request.form.get("email"),
            password=hash_and_salted_password
        )

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    return render_template("register.html", form=form)


@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if request.method == "POST":
        password = request.form.get('password')

        # Find user by email entered.
        user = BlogUser.query.filter_by(email=request.form.get('email')).first()
        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            else:
                flash('Password incorrect, please try again.')
                return redirect(url_for('login', form=form))
        else:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login', form=form))
    else:
        return render_template("login.html", form=form)

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template("post.html", post=requested_post)

@app.route("/post/user/<int:post_id>" , methods=['GET', 'POST'])
@login_required
def show_post_as_user(post_id):
    form = CommentForm()
    requested_post = BlogPost.query.get(post_id)
    users = BlogUser.query.all()
    comments = UserComment.query.all()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_comment = UserComment(
                user_id = current_user.id,
                comment=form.comment.data,
                current_post= post_id
            )
            db.session.add(new_comment)
            db.session.commit()
            return render_template("post.html", post=requested_post, logged_in=True, user=current_user, form=form,
                                   comment=comments, all_users=users)

    return render_template("post.html", post=requested_post, logged_in=True, user=current_user, form=form,
                           comment=comments, all_users = users)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET','POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if request.method == 'POST':
        if form.validate_on_submit():
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user.name,
                date=date.today().strftime("%B %d, %Y"),
                author_id = current_user.id
            )
            db.session.add(new_post)
            db.session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in= True)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id),logged_in= True)

    return render_template("make-post.html", form=edit_form,logged_in= True)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
