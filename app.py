from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///bookshelf.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = '12345'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
login_manager = LoginManager()
login_manager.init_app(app)


# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_student = db.Column(db.Boolean, default=True)
    is_instructor = db.Column(db.Boolean, default=False)  # New column

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
class Book(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    genre = db.Column(db.String(50))
    read = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    books = Book.query.filter_by(user_id=current_user.id).all()
    return "List of books: " + str([book.title for book in books])

@app.route('/add', methods=['POST'])
@login_required
def add_book():
    data = request.get_json()
    title = data.get('title')
    author = data.get('author')
    genre = data.get('genre')
    new_book = Book(title=title, author=author, genre=genre, user_id=current_user.id)
    db.session.add(new_book)
    db.session.commit()
    return jsonify({'message': 'Book added successfully!'})

@app.route('/edit/<int:book_id>', methods=['PUT'])
@login_required
def edit_book(book_id):
    book = Book.query.get_or_404(book_id)
    data = request.get_json()
    book.title = data.get('title')
    book.author = data.get('author')
    book.genre = data.get('genre')
    db.session.commit()
    return jsonify({'message': 'Book updated successfully!'})

@app.route('/delete/<int:book_id>', methods=['DELETE'])
@login_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    db.session.delete(book)
    db.session.commit()
    return jsonify({'message': 'Book deleted successfully!'})

@app.route('/search', methods=['POST'])
@login_required
def search():
    data = request.get_json()
    search_term = data.get('search_term')
    books = Book.query.filter_by(user_id=current_user.id).filter(Book.title.like(f'%{search_term}%') | Book.author.like(f'%{search_term}%') | Book.genre.like(f'%{search_term}%')).all()
    return "Search results: " + str([book.title for book in books])

@app.route('/mark_read/<int:book_id>', methods=['PUT'])
@login_required
def mark_read(book_id):
    book = Book.query.get_or_404(book_id)
    book.read = True
    db.session.commit()
    return jsonify({'message': 'Book marked as read!'})

@app.route('/mark_unread/<int:book_id>', methods=['PUT'])
@login_required
def mark_unread(book_id):
    book = Book.query.get_or_404(book_id)
    book.read = False
    db.session.commit()
    return jsonify({'message': 'Book marked as unread!'})

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists. Please choose a different one.'}), 400
    new_user = User(username=username)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Account created successfully! You can now log in.'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        access_token = create_access_token(identity=user.id)
        return jsonify({'access_token': access_token}), 200
    else:
        return jsonify({'error': 'Invalid username or password.'}), 401

@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    
    return jsonify({'message': 'Logged out successfully!'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

