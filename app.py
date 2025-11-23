"""DatingApp - A simple Flask dating application with photo upload."""
import os
import sqlite3
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image
import io

app = Flask(__name__)
app.secret_key = 'dating-app-secret-key-change-in-production'

# Upload configuration
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE

# Database setup
DATABASE = 'dating.db'

def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize database with tables."""
    db = get_db()
    cursor = db.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT,
            age INTEGER,
            bio TEXT,
            photo_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Likes table (who liked whom)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS likes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            liker_id INTEGER NOT NULL,
            liked_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (liker_id) REFERENCES users(id),
            FOREIGN KEY (liked_id) REFERENCES users(id),
            UNIQUE(liker_id, liked_id)
        )
    ''')
    
    # Matches table (mutual likes)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user1_id) REFERENCES users(id),
            FOREIGN KEY (user2_id) REFERENCES users(id),
            UNIQUE(user1_id, user2_id)
        )
    ''')
    
    # Messages table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            match_id INTEGER NOT NULL,
            sender_id INTEGER NOT NULL,
            text TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (match_id) REFERENCES matches(id),
            FOREIGN KEY (sender_id) REFERENCES users(id)
        )
    ''')
    
    # Notifications table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            type TEXT NOT NULL,
            sender_id INTEGER,
            match_id INTEGER,
            message TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (match_id) REFERENCES matches(id)
        )
    ''')
    
    db.commit()
    db.close()

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in first', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes - Authentication
@app.route('/')
def index():
    """Home page."""
    if 'user_id' in session:
        return redirect(url_for('discover'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        password_confirm = request.form.get('password_confirm', '')
        
        # Validation
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters', 'error')
            return redirect(url_for('register'))
        
        if not email or '@' not in email:
            flash('Valid email required', 'error')
            return redirect(url_for('register'))
        
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('register'))
        
        if password != password_confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        try:
            db = get_db()
            cursor = db.cursor()
            password_hash = generate_password_hash(password)
            cursor.execute(
                'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                (username, email, password_hash)
            )
            db.commit()
            db.close()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
            return redirect(url_for('register'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        db.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(url_for('discover'))
        
        flash('Invalid email or password', 'error')
        return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout."""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

# Routes - Profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """View and edit user profile."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    if request.method == 'POST':
        name = request.form.get('name', '')
        age = request.form.get('age', '', type=int)
        bio = request.form.get('bio', '')
        
        # Handle file upload
        photo_url = None
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '' and allowed_file(file.filename):
                try:
                    # Read and validate image
                    img = Image.open(file)
                    
                    # Resize image
                    img.thumbnail((800, 800))
                    
                    # Save image
                    filename = secure_filename(f'user_{user_id}_{int(datetime.now().timestamp())}.jpg')
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    img.save(filepath, 'JPEG')
                    
                    photo_url = f'/static/uploads/{filename}'
                    flash('Photo uploaded successfully!', 'success')
                except Exception as e:
                    flash(f'Error uploading photo: {str(e)}', 'error')
                    photo_url = None
        else:
            # Get existing photo if not uploading new one
            cursor.execute('SELECT photo_url FROM users WHERE id = ?', (user_id,))
            existing = cursor.fetchone()
            photo_url = existing['photo_url'] if existing and existing['photo_url'] else None
        
        # Only update if we have a new photo or explicitly clearing it
        if photo_url or 'photo' in request.files:
            cursor.execute(
                'UPDATE users SET name = ?, age = ?, bio = ?, photo_url = ? WHERE id = ?',
                (name if name else None, age if age else None, bio if bio else None, photo_url, user_id)
            )
        else:
            cursor.execute(
                'UPDATE users SET name = ?, age = ?, bio = ? WHERE id = ?',
                (name if name else None, age if age else None, bio if bio else None, user_id)
            )
        
        db.commit()
        flash('Profile updated!', 'success')
    
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    db.close()
    
    return render_template('profile.html', user=user)

@app.route('/api/delete-account', methods=['POST'])
@login_required
def api_delete_account():
    """Delete user account and all related data."""
    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    
    try:
        # Delete all notifications for this user
        cursor.execute('DELETE FROM notifications WHERE user_id = ? OR sender_id = ?', 
                      (user_id, user_id))
        
        # Delete all messages in matches involving this user
        cursor.execute('''
            DELETE FROM messages 
            WHERE match_id IN (
                SELECT id FROM matches 
                WHERE user1_id = ? OR user2_id = ?
            )
        ''', (user_id, user_id))
        
        # Delete all matches involving this user
        cursor.execute('DELETE FROM matches WHERE user1_id = ? OR user2_id = ?', 
                      (user_id, user_id))
        
        # Delete all likes made by or received by this user
        cursor.execute('DELETE FROM likes WHERE liker_id = ? OR liked_id = ?', 
                      (user_id, user_id))
        
        # Delete the user account
        cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
        
        db.commit()
        db.close()
        
        # Clear session
        session.clear()
        
        return jsonify({'success': True, 'message': 'Account deleted successfully'}), 200
    
    except Exception as e:
        db.close()
        return jsonify({'error': str(e)}), 500

# Routes - Discover/Swiping
@app.route('/discover')
@login_required
def discover():
    """Discover and swipe on profiles."""
    return render_template('discover.html')

@app.route('/api/discover-profiles')
@login_required
def api_discover_profiles():
    """Get profiles to discover (REST API)."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    # Get users already liked by current user
    cursor.execute('SELECT liked_id FROM likes WHERE liker_id = ?', (user_id,))
    liked_ids = [row['liked_id'] for row in cursor.fetchall()]
    
    # Get matched users
    cursor.execute(
        'SELECT user1_id, user2_id FROM matches WHERE user1_id = ? OR user2_id = ?',
        (user_id, user_id)
    )
    matched_ids = []
    for row in cursor.fetchall():
        matched_ids.append(row['user2_id'] if row['user1_id'] == user_id else row['user1_id'])
    
    exclude_ids = [user_id] + liked_ids + matched_ids
    placeholders = ','.join('?' * len(exclude_ids))
    
    cursor.execute(
        f'SELECT id, username, name, age, bio, photo_url FROM users WHERE id NOT IN ({placeholders}) LIMIT 20',
        exclude_ids
    )
    profiles = [dict(row) for row in cursor.fetchall()]
    db.close()
    
    return jsonify(profiles)

@app.route('/api/like/<int:user_id>', methods=['POST'])
@login_required
def api_like(user_id):
    """Like a user."""
    liker_id = session['user_id']
    
    if liker_id == user_id:
        return jsonify({'error': 'Cannot like yourself'}), 400
    
    db = get_db()
    cursor = db.cursor()
    
    try:
        cursor.execute(
            'INSERT INTO likes (liker_id, liked_id) VALUES (?, ?)',
            (liker_id, user_id)
        )
        
        # Create like notification for the liked user
        cursor.execute(
            'INSERT INTO notifications (user_id, type, sender_id, message) VALUES (?, ?, ?, ?)',
            (user_id, 'like', liker_id, f'Someone liked your profile!')
        )
        
        # Check for mutual like
        cursor.execute(
            'SELECT * FROM likes WHERE liker_id = ? AND liked_id = ?',
            (user_id, liker_id)
        )
        mutual = cursor.fetchone()
        
        if mutual:
            # Create match
            cursor.execute(
                'INSERT INTO matches (user1_id, user2_id) VALUES (?, ?)',
                (liker_id, user_id)
            )
            
            # Get the match ID
            match_id = cursor.lastrowid
            
            # Create notifications for both users
            cursor.execute(
                'INSERT INTO notifications (user_id, type, sender_id, match_id, message) VALUES (?, ?, ?, ?, ?)',
                (user_id, 'match', liker_id, match_id, f'You have a new match!')
            )
            cursor.execute(
                'INSERT INTO notifications (user_id, type, sender_id, match_id, message) VALUES (?, ?, ?, ?, ?)',
                (liker_id, 'match', user_id, match_id, f'You have a new match!')
            )
            
            db.commit()
            db.close()
            return jsonify({'match': True, 'message': "It's a match! 🎉"}), 201
        
        db.commit()
        db.close()
        return jsonify({'match': False}), 200
    
    except sqlite3.IntegrityError:
        db.close()
        return jsonify({'error': 'Already liked this user'}), 400

# Routes - Chat/Matches
@app.route('/matches')
@login_required
def matches():
    """View matches and chat."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    cursor.execute('''
        SELECT m.id, 
               CASE WHEN m.user1_id = ? THEN m.user2_id ELSE m.user1_id END as other_user_id,
               CASE WHEN m.user1_id = ? THEN u2.username ELSE u1.username END as other_username,
               CASE WHEN m.user1_id = ? THEN u2.photo_url ELSE u1.photo_url END as other_photo_url,
               m.created_at
        FROM matches m
        JOIN users u1 ON m.user1_id = u1.id
        JOIN users u2 ON m.user2_id = u2.id
        WHERE m.user1_id = ? OR m.user2_id = ?
        ORDER BY m.created_at DESC
    ''', (user_id, user_id, user_id, user_id, user_id))
    
    user_matches = cursor.fetchall()
    db.close()
    
    return render_template('matches.html', matches=user_matches)

@app.route('/chat/<int:match_id>')
@login_required
def chat(match_id):
    """Chat with matched user."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    # Verify user is part of match
    cursor.execute('SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
                   (match_id, user_id, user_id))
    match = cursor.fetchone()
    
    if not match:
        flash('Match not found', 'error')
        return redirect(url_for('matches'))
    
    # Get other user info
    other_user_id = match['user2_id'] if match['user1_id'] == user_id else match['user1_id']
    cursor.execute('SELECT id, username, name, photo_url FROM users WHERE id = ?', (other_user_id,))
    other_user = cursor.fetchone()
    
    # Get messages
    cursor.execute('''
        SELECT sender_id, text, created_at FROM messages 
        WHERE match_id = ? 
        ORDER BY created_at ASC
    ''', (match_id,))
    messages = cursor.fetchall()
    db.close()
    
    return render_template('chat.html', match_id=match_id, other_user=other_user, 
                         messages=messages, current_user_id=user_id)

@app.route('/api/chat/<int:match_id>/send', methods=['POST'])
@login_required
def api_send_message(match_id):
    """Send a message."""
    data = request.get_json()
    text = data.get('text', '').strip()
    
    if not text:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    user_id = session['user_id']
    
    db = get_db()
    cursor = db.cursor()
    
    # Verify user is part of match
    cursor.execute('SELECT * FROM matches WHERE id = ? AND (user1_id = ? OR user2_id = ?)',
                   (match_id, user_id, user_id))
    match = cursor.fetchone()
    
    if not match:
        return jsonify({'error': 'Unauthorized'}), 403
    
    cursor.execute(
        'INSERT INTO messages (match_id, sender_id, text) VALUES (?, ?, ?)',
        (match_id, user_id, text)
    )
    
    # Get the recipient ID
    recipient_id = match['user2_id'] if match['user1_id'] == user_id else match['user1_id']
    
    # Create message notification for the recipient
    cursor.execute(
        'INSERT INTO notifications (user_id, type, sender_id, match_id, message) VALUES (?, ?, ?, ?, ?)',
        (recipient_id, 'message', user_id, match_id, f'You have a new message!')
    )
    
    db.commit()
    db.close()
    
    return jsonify({'success': True}), 201

# Routes - Notifications
@app.route('/notifications')
@login_required
def notifications():
    """View notifications."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    cursor.execute('''
        SELECT n.id, n.type, n.message, n.is_read, n.created_at, n.match_id,
               u.username, u.name, u.photo_url
        FROM notifications n
        LEFT JOIN users u ON n.sender_id = u.id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC
    ''', (user_id,))
    
    user_notifications = cursor.fetchall()
    db.close()
    
    return render_template('notifications.html', notifications=user_notifications)

@app.route('/api/notifications')
@login_required
def api_get_notifications():
    """Get unread notifications count."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    cursor.execute('SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0',
                   (user_id,))
    result = cursor.fetchone()
    db.close()
    
    return jsonify({'unread_count': result['count']}), 200

@app.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """Mark notification as read."""
    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    
    cursor.execute('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
                   (notification_id, user_id))
    db.commit()
    db.close()
    
    return jsonify({'success': True}), 200

if __name__ == '__main__':
    # Initialize database
    init_db()
    # Run app
    app.run(debug=True, host='127.0.0.1', port=5000)
