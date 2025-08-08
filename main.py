from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
# Import your forms from the forms.py
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm

app = Flask(__name__)
app.config['SECRET_KEY'] = 'TopSecretAPIKey'
ckeditor = CKEditor(app)
Bootstrap5(app)

# TODO: Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)

def admin_only(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id == 1:
                return func(*args, **kwargs)
            else:
                return abort(403)
        else:
            return abort(403)
    return wrapper

# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy(model_class=Base)
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("all_users.id"))
    author = db.relationship("Users", back_populates="posts")
    comments = db.relationship("Comment", back_populates="blogpost")


# TODO: Create a User table for all your registered users. 
class Users(UserMixin, db.Model):
    __tablename__ = "all_users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String(250), nullable=False)
    name: Mapped[str] = mapped_column(String(250), nullable=False)

    posts = db.relationship("BlogPost", back_populates="author")
    comments = db.relationship("Comment", back_populates="commenter")

class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(), nullable=False)

    commenter_id = db.Column(db.Integer, db.ForeignKey("all_users.id"))
    commenter = db.relationship("Users", back_populates="comments")

    blogpost_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    blogpost = db.relationship("BlogPost", back_populates="comments")

with app.app_context():
    db.create_all()


# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["POST", "GET"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, salt_length=2)
        try:
            new_user = Users(
                email=form.email.data,
                password=hashed_password,
                name=form.name.data
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash("Successfully registered!", category='success')
            return redirect(url_for('get_all_posts'))
        except IntegrityError:
            flash("You've already signed up with that email, Log In instead.", category='error')
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login', methods=["POST", "GET"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.execute(db.select(Users).where(Users.email == form.email.data)).scalar()
        if user is not None:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                flash("Successfully logged in!", category='success')
                return redirect(url_for('get_all_posts'))
            else:
                flash("Incorrect password, please try again.", category='error')
                return render_template("login.html", form=form)
        else:
            flash("That email does not exist, please try again.", category='error')
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    if current_user.is_authenticated:
        return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated, id=current_user.id)
    else:
        return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    all_comments = db.session.execute(db.select(Comment).where(Comment.blogpost_id == post_id).order_by(Comment.id.desc())).scalars()
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            blogpost = db.session.execute(db.select(BlogPost).where(BlogPost.id == post_id)).scalar()
            new_comment = Comment(
                text=form.comment.data,
                blogpost_id=post_id,
                blogpost=blogpost,
                commenter_id=current_user.id,
                commenter=current_user,
            )
            db.session.add(new_comment)
            db.session.commit()
            return redirect(url_for('show_post', post_id=post_id))
        else:
            flash("You need to login or register first to comment.", category='error')
            return redirect(url_for('login'))
    if current_user.is_authenticated:
        return render_template("post.html", all_comments=all_comments, post=requested_post, logged_in=current_user.is_authenticated, id=current_user.id, form=form)
    else:
        return render_template("post.html", all_comments=all_comments, post=requested_post, logged_in=current_user.is_authenticated, form=form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True, logged_in=current_user.is_authenticated)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=True, port=5002)
