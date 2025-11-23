# DatingApp 💕

A modern, feature-rich dating application built with Flask and SQLite. Users can create profiles, discover other users, like profiles, match with compatible users, chat with matches, and manage notifications.

## Features

### User Authentication
- User registration with email validation
- Secure login system with password hashing
- Session management
- Account deletion with data cleanup

### Profile Management
- Create and edit user profiles
- Upload and display profile photos
- Set age, name, and bio information
- Photo resizing and optimization

### Discovery & Matching
- Browse and discover other user profiles
- Swipe functionality (Like/Pass)
- Automatic match creation when mutual likes occur
- View matched profiles

### Messaging
- Real-time chat with matched users
- Message history persistence
- Send and receive messages

### Notifications
- Like notifications (when someone likes your profile)
- Match notifications (when you get a match)
- Message notifications (when someone sends a message)
- Mark notifications as read
- Quick reply and action buttons from notifications

### User Interface
- Modern, responsive design
- Beautiful gradient background
- Intuitive navigation
- Mobile-friendly layout
- Real-time updates

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLite3
- **Frontend**: HTML5, CSS3, JavaScript (Vanilla)
- **Security**: Werkzeug (password hashing)
- **Image Processing**: Pillow (PIL)

## Installation

### Requirements
- Python 3.8+
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/yourusername/DatingApp.git
cd DatingApp
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python app.py
```

4. Open your browser and navigate to:
```
http://localhost:5000
```

## Database Schema

### Tables
- **users**: Store user account information
- **likes**: Track who liked whom
- **matches**: Store mutual match relationships
- **messages**: Store chat messages between matches
- **notifications**: Store user notifications

## Usage

1. **Register**: Create a new account with email and password
2. **Profile**: Add your photo, name, age, and bio
3. **Discover**: Browse other profiles and like those you're interested in
4. **Match**: Get notifications when someone likes you back
5. **Chat**: Message your matches in real-time
6. **Notifications**: View all your likes, matches, and messages in one place

## API Endpoints

### Authentication
- `POST /register` - User registration
- `POST /login` - User login
- `GET /logout` - User logout

### Profile
- `GET /profile` - View user profile
- `POST /profile` - Update user profile

### Discovery
- `GET /discover` - Discover profiles page
- `GET /api/discover-profiles` - Get profiles to discover

### Matching & Likes
- `POST /api/like/<user_id>` - Like a user

### Matches
- `GET /matches` - View user matches
- `GET /chat/<match_id>` - View chat with a match

### Messaging
- `POST /api/chat/<match_id>/send` - Send a message

### Notifications
- `GET /notifications` - View all notifications
- `GET /api/notifications` - Get unread notification count
- `POST /api/notifications/<id>/read` - Mark notification as read

### Account
- `POST /api/delete-account` - Delete user account

## Environment Variables

None required for development. For production, consider setting:
- `FLASK_ENV=production`
- `SECRET_KEY` (change from default)

## Security Notes

⚠️ **For Production Deployment:**
- Change `app.secret_key` to a secure random value
- Use a production WSGI server (Gunicorn, uWSGI)
- Enable HTTPS
- Set `DEBUG=False`
- Use environment variables for sensitive configuration
- Implement rate limiting
- Add CSRF protection

## File Structure

```
DatingApp/
├── app.py              # Main Flask application
├── requirements.txt    # Python dependencies
├── dating.db          # SQLite database (auto-created)
├── static/
│   └── uploads/       # User profile photos
└── templates/
    ├── base.html      # Base template with navigation
    ├── login.html     # Login page
    ├── register.html  # Registration page
    ├── profile.html   # User profile page
    ├── discover.html  # Discovery/swiping page
    ├── matches.html   # Matches list page
    ├── chat.html      # Chat page
    └── notifications.html  # Notifications page
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

MIT License - feel free to use this project for personal or commercial purposes.

## Author

Designed by **Shaktiranjan**

## Support

For issues, questions, or suggestions, please open an issue on GitHub.

---

Made with ❤️ by Shaktiranjan
