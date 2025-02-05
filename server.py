from flask import Flask, render_template, request, redirect, session
from flask_socketio import SocketIO, send
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "h4ck3r_s3cr3t"  # Secret key for session management
socketio = SocketIO(app, cors_allowed_origins="*")
bcrypt = Bcrypt(app)

users = {}  # Stores usernames and hashed passwords

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if username in users:
            if bcrypt.check_password_hash(users[username], password):
                session["username"] = username
                return redirect("/chat")
            else:
                return render_template("login.html", error="Wrong password! Try again.")
        else:
            hashed_pw = bcrypt.generate_password_hash(password).decode("utf-8")
            users[username] = hashed_pw
            session["username"] = username
            return redirect("/chat")

    return render_template("login.html", error=None)

@app.route("/chat")
def chat():
    if "username" not in session:
        return redirect("/")
    return render_template("chat.html", username=session["username"])

@socketio.on("message")
def handle_message(msg):
    send(f"{session['username']}: {msg}", broadcast=True)  # Broadcast message with username

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
