from flask import Flask, render_template, redirect, request, flash, session			# same as before
from flask_sqlalchemy import SQLAlchemy			# instead of mysqlconnection
from sqlalchemy.sql import func, expression     # ADDED THIS LINE FOR DEFAULT TIMESTAMP
from flask_migrate import Migrate			# this is new
from flask_bcrypt import Bcrypt
import re
app = Flask(__name__)
app.secret_key = "thisisanexam"
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# configurations to tell our app about the database we'll be connecting to
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///belt_exam.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# an instance of the ORM
db = SQLAlchemy(app)
# a tool for allowing migrations/creation of tables
migrate = Migrate(app, db)
#### ADDING THIS CLASS ####
# the db.Model in parentheses tells SQLAlchemy that this class represents a table in our database
class User(db.Model):	
    __tablename__ = "users"    # optional		
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255))
    pw = db.Column(db.String(255))
    confirm_pw = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, server_default=func.now())    # notice the extra import statement above
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())

class Post(db.Model):	
    __tablename__ = "posts"    # optional		
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # author = db.relationship('User', foreign_keys=[author_id], backref="posts", cascade="all")
    author = db.relationship('User', foreign_keys=[author_id], backref="posts")
    created_at = db.Column(db.DateTime, server_default=func.now())    # notice the extra import statement above
    updated_at = db.Column(db.DateTime, server_default=func.now(), onupdate=func.now())
    not_granted = db.Column(db.Boolean, server_default=expression.true(), nullable=False)


# routes go here...
@app.route('/')
def home_page():
    all_users = User.query.all()
    # all_ninjas = Ninjas.query.all()
    return render_template('home.html', users=all_users)

@app.route('/register', methods=['POST'])
def on_register():
    is_valid = True

    if len(request.form['fn']) < 1:
        is_valid = False
        flash("First name cannot be blank")

    if len(request.form['ln']) < 1:
        is_valid = False
        flash("Last name cannot be blank")
    
    if len(request.form['pw']) < 1:
        is_valid = False
        flash("Password cannot be blank")

    if request.form['pw'] != request.form['c_pw']:
        is_valid = False
        flash("Password don't match.")

    if not EMAIL_REGEX.match(request.form['em']):
        is_valid = False
        flash("Please use a valid email.")

    if not is_valid:
        return redirect('/')
    else:
        hashed_pw = bcrypt.generate_password_hash(request.form['pw'])

        new_user = User(first_name=request.form['fn'], last_name=request.form['ln'], email=request.form['em'], pw=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        print(new_user)
        return redirect('/wishes')

@app.route('/login', methods=['POST'])
def on_login():
    is_valid = True

    if len(request.form['em']) < 1:
        is_valid = False
        flash("Email cannot be blank.")
    
    if not EMAIL_REGEX.match(request.form['em']):
        is_valid = False
        flash("Please use a valid email.")

    if is_valid:
        user_with_correct_email = User.query.filter_by(email=request.form['em']).all()

        if user_with_correct_email:
            #verify pw
            # user = user_with_correct_email[0]

            if bcrypt.check_password_hash(user_with_correct_email[0].pw, request.form['pw']):
                session['id'] = user_with_correct_email[0].id
                return redirect('/wishes')

            else:
                flash("Password is not valid.")
                return redirect('/')
        else:
            flash("Email is not valid.")
            return redirect('/')
    else:
        return redirect('/')

@app.route('/wishes')
def landing():
    if 'id' not in session:
        return redirect('/')
    print("******")
    user_with_correct_id = User.query.filter_by(id=session['id']).all()
    if user_with_correct_id:
        # user_data = user_with_correct_id[0].first_name
        # user_data = user_with_correct_id[0]
        user_data =  {}
        user_data['first_name'] = user_with_correct_id[0].first_name
        print(session['id'])
        wish_list = Post.query.filter_by(not_granted=True, author_id=session['id']).all()
        print(wish_list)
        granted_list = Post.query.filter_by(not_granted=False).all()
    else:
        return redirect('/')

    return render_template('landing.html', user = user_data, wishes = wish_list, granted_wishes=granted_list)

@app.route('/logout')
def on_logout():
    session.clear()
    return redirect('/')

@app.route('/wishes/new')
def new_wish():
    if 'id' not in session:
        return redirect('/')
    print("******")
    print(session['id'])
    user_with_correct_id = User.query.filter_by(id=session['id']).all()
    
    print(user_with_correct_id)
    if user_with_correct_id:
        user_data =  {}
        user_data['first_name'] = user_with_correct_id[0].first_name
    else:
        return redirect('/')
    return render_template('new_wish.html', user = user_data)

@app.route('/create_wish', methods=['GET','POST'])
def create_wish():
    if request.method == "POST":
        is_valid = True

        if len(request.form['title']) < 3:
            is_valid = False
            flash("Wish should be at least 3 characters.")

        if len(request.form['content']) < 3:
            is_valid = False
            flash("Description should be at least 3 characters.")    
        if is_valid:
            create_wish = Post(title=request.form['title'], content=request.form['content'], author_id=session['id'])
            db.session.add(create_wish)
            db.session.commit()
            print(create_wish)
            return redirect('/wishes')
        else:
            return redirect('/wishes/new')
    else:
        return redirect('/wishes')

@app.route('/remove', methods=['POST'])
def remove():
    print('********')
    print(request.form)
    print(request.form['wishid'])
    print(type(request.form['wishid']))
    wish_to_delete = Post.query.get(int(request.form['wishid']))
    db.session.delete(wish_to_delete)
    db.session.commit()
    print(wish_to_delete)
    return redirect('/wishes')

@app.route('/granted', methods=['POST'])
def granted():

    wish = Post.query.get(int(request.form['wishid']))
    wish.not_granted = False
    db.session.commit()
    # granted_wish = Post(title=wish.title, content=wish.content,)

    return redirect('/wishes')

@app.route('/edit/<id>')
def edit_wish(id):
    if 'id' not in session:
        return redirect('/')
    user_with_correct_id = User.query.filter_by(id=session['id']).all()

    if user_with_correct_id:
        user_data =  {}
        user_data['first_name'] = user_with_correct_id[0].first_name
        user_data['wish_id'] = id
    else:
        return redirect('/')
    return render_template('edit_wish.html', user = user_data)

@app.route('/edit_wish', methods=['POST'])
def editing_wish():
    is_valid = True

    if len(request.form['title']) < 3:
        is_valid = False
        flash("Wish should be at least 3 characters.")

    if len(request.form['content']) < 3:
        is_valid = False
        flash("Description should be at least 3 characters.")    
    if is_valid:
        # wish_with_correct_content = Post.query.filter_by(content=request.form['content']).all()
        # session['wish_id'] = wish_with_correct_content[0]
        print(request.form['wishid'])
        edit_wish = Post.query.get(request.form['wishid'])
        edit_wish.title=request.form['title']
        edit_wish.content=request.form['content']
        db.session.commit()
        print(edit_wish)
        return redirect('/wishes')
    else:
        return redirect('/edit/' + request.form['wishid'])

if __name__ == "__main__":
    app.run(debug=True)