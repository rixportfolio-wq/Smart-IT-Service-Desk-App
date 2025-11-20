from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from datetime import datetime
import os

app = Flask(__name__)
app.secret_key = "supersecretkey"  # needed for sessions

DB_PATH = "/var/data/tickets.db"
os.makedirs("/var/data", exist_ok=True)

# -----------------------------------------
# DATABASE SETUP
# -----------------------------------------

def add_missing_columns(conn, table, columns):
    cur = conn.cursor()
    
    # Get existing columns
    cur.execute(f"PRAGMA table_info({table})")
    existing = [row[1] for row in cur.fetchall()]

    # Add missing columns
    for col, definition in columns.items():
        if col not in existing:
            print(f"Adding missing column: {col}")
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {definition}")

    conn.commit()


def init_db():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # USERS TABLE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT,
            email TEXT UNIQUE,
            password TEXT,
            role TEXT DEFAULT 'employee',
            created_at TEXT
        )
    """)

    # TICKETS TABLE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT,
            description TEXT,
            created_by INTEGER,
            created_at TEXT,
            updated_at TEXT,
            priority TEXT DEFAULT 'Low',
            status TEXT DEFAULT 'Open',
            assigned_to INTEGER,
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(assigned_to) REFERENCES users(id)
        )
    """)

    # Add missing column: is_internal (0 = public, 1 = internal)
    try:
        cur.execute("ALTER TABLE ticket_comments ADD COLUMN is_internal INTEGER DEFAULT 0")
    except:
        pass


    # COMMENTS TABLE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ticket_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ticket_id INTEGER,
            user_id INTEGER,
            comment TEXT,
            created_at TEXT,
            FOREIGN KEY(ticket_id) REFERENCES tickets(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # KNOWLEDGE BASE
    cur.execute("""
        CREATE TABLE IF NOT EXISTS knowledge_base (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT,
            answer TEXT,
            category TEXT,
            created_at TEXT
        )
    """)

    # SYSTEM LOGS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    # AUTO-ADD MISSING COLUMNS (PREVENT ERRORS)
    add_missing_columns(conn, "tickets", {
        "assigned_to": "assigned_to INTEGER",
        "priority": "priority TEXT DEFAULT 'Low'",
        "status": "status TEXT DEFAULT 'Open'",
        "updated_at": "updated_at TEXT"
    })


    # Create default admin if none exists
    cur.execute("SELECT * FROM users")
    if not cur.fetchone():
        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES ('admin', 'admin123', 'Admin')
        """)

        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES ('employee', '12345', 'Employee')
        """)

        cur.execute("""
            INSERT INTO users (username, password, role)
            VALUES ('staff', '12345', 'IT Staff')
        """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized successfully.")

init_db()

def ensure_ticket_columns(conn):
    cur = conn.cursor()

    # Get existing columns
    cur.execute("PRAGMA table_info(tickets)")
    cols = [col[1] for col in cur.fetchall()]

    # Add missing columns automatically
    if "assigned_to" not in cols:
        cur.execute("ALTER TABLE tickets ADD COLUMN assigned_to TEXT")

    if "priority" not in cols:
        cur.execute("ALTER TABLE tickets ADD COLUMN priority TEXT DEFAULT 'Low'")

    if "status" not in cols:
        cur.execute("ALTER TABLE tickets ADD COLUMN status TEXT DEFAULT 'Open'")

    if "updated_at" not in cols:
        cur.execute("ALTER TABLE tickets ADD COLUMN updated_at TEXT")

    conn.commit()



# -----------------------------------------
# LOGIN REQUIRED DECORATOR
# -----------------------------------------
def login_required(func):
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


knowledge_base = [
    {
        "id": 1,
        "title": "How to Reset Your Password",
        "category": "Account",
        "short": "Forgot your password? Follow these steps to reset it safely.",
        "content": """
        <h5>Resetting Your Password</h5>
        <p>To reset your password, follow these steps:</p>
        <ol>
          <li>Go to <strong>Settings → Account</strong></li>
          <li>Click <strong>Reset Password</strong></li>
          <li>Check your email for the reset link</li>
        </ol>
        <p>If this doesn't work, submit a ticket.</p>
        """
    },
    {
        "id": 2,
        "title": "Fixing WiFi / Internet Issues",
        "category": "Network",
        "short": "Try these steps if you're having connection problems.",
        "content": """
        <h5>Troubleshooting WiFi</h5>
        <ul>
          <li>Restart your router or modem</li>
          <li>Reconnect to the WiFi network</li>
          <li>Check if other devices also have issues</li>
          <li>Ensure your LAN cable is properly connected (if wired)</li>
        </ul>
        """
    },
    {
        "id": 3,
        "title": "Requesting New Software",
        "category": "Software",
        "short": "Need new software? Here's how to request an installation.",
        "content": """
        <h5>Software Request Process</h5>
        <p>Submit a ticket with the software name, version, and purpose.</p>
        <p>IT will verify licensing and install it for you.</p>
        """
    },
    {
        "id": 4,
        "title": "How to Map Network Drives",
        "category": "Network",
        "short": "Access shared folders from the server.",
        "content": """
        <h5>Mapping a Network Drive</h5>
        <ol>
          <li>Open File Explorer</li>
          <li>Select <strong>Map Network Drive</strong></li>
          <li>Enter the server path (e.g., \\\\server\\department)</li>
          <li>Check 'Reconnect at sign-in'</li>
        </ol>
        """
    }
]


# -----------------------------------------
# ROUTES
# -----------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = request.form["username"]
        pw = request.form["password"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (user, pw))
        account = cur.fetchone()
        conn.close()

        if account:
            session["username"] = account[1]
            session["role"] = account[3]
            return redirect("/")
        else:
            return render_template("login.html", error="Invalid credentials")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@login_required
def dashboard():
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # Employee sees only their own tickets
    if session["role"] == "Employee":
        cur.execute("SELECT * FROM tickets WHERE created_by=?", (session["username"],))
    else:
        cur.execute("SELECT * FROM tickets")

    tickets = cur.fetchall()
    conn.close()

    total = len(tickets)
    open_count = sum(1 for t in tickets if t[4] == "Open")
    progress = sum(1 for t in tickets if t[4] == "In Progress")
    resolved = sum(1 for t in tickets if t[4] == "Resolved")

    return render_template("dashboard.html",
                           total=total,
                           open=open_count,
                           progress=progress,
                           resolved=resolved,
                           tickets=tickets)


@app.route("/new", methods=["GET", "POST"])
@login_required
def new_ticket():
    if request.method == "POST":
        title = request.form["title"]
        category = request.form["category"]
        priority = request.form["priority"]
        description = request.form["description"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO tickets (title, category, priority, status, description, created_by)
            VALUES (?, ?, ?, 'Open', ?, ?)
        """, (title, category, priority, description, session["username"]))
        conn.commit()
        conn.close()

        return redirect("/")

    return render_template("new_ticket.html")


@app.route("/tickets")
def view_tickets():
    if "role" not in session:
        return redirect("/login")

    role = session["role"]
    username = session["username"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    if role == "Admin":
        # Admin sees all tickets
        c.execute("SELECT * FROM tickets ORDER BY id DESC")

    elif role == "IT Staff":
        # IT Staff only sees tickets assigned to them
        c.execute("SELECT * FROM tickets WHERE assigned_to = ? ORDER BY id DESC", (username,))

    else:
        # Normal Users see only their own tickets
        c.execute("SELECT * FROM tickets WHERE created_by = ? ORDER BY id DESC", (username,))

    tickets = c.fetchall()
    conn.close()

    return render_template("tickets.html", tickets=tickets)



# ------------------------------
# UPDATE TICKET STATUS
# ------------------------------
@app.route("/update_status/<int:ticket_id>", methods=["POST"])
@login_required
def update_status(ticket_id):
    if session["role"] not in ["IT Staff", "Admin"]:
        return "Access Denied"

    new_status = request.form["status"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("UPDATE tickets SET status=? WHERE id=?", (new_status, ticket_id))
    conn.commit()
    conn.close()

    return redirect(f"/ticket/{ticket_id}")


# ------------------------------
# ASSIGN TICKET TO STAFF
# ------------------------------
@app.route("/assign/<int:ticket_id>", methods=["POST"])
@login_required
def assign(ticket_id):
    if session["role"] not in ["IT Staff", "Admin"]:
        return "Access Denied"

    assigned_to = request.form["assigned_to"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("UPDATE tickets SET assigned_to=? WHERE id=?", (assigned_to, ticket_id))
    conn.commit()
    conn.close()

    return redirect(f"/ticket/{ticket_id}")


@app.route("/assign_ticket/<int:ticket_id>", methods=["POST"])
def assign_ticket(ticket_id):
    if session.get("role") != "Admin":
        return "Unauthorized", 403

    assigned_to = request.form["assigned_to"]

    conn = sqlite3.connect("database.db")
    c = conn.cursor()
    c.execute("UPDATE tickets SET assigned_to = ? WHERE id = ?", (assigned_to, ticket_id))
    conn.commit()
    conn.close()

    return redirect(url_for("ticket_details", ticket_id=ticket_id))


# -----------------------------------------
# TICKET DETAILS ROUTE
# -----------------------------------------
@app.route("/ticket/<int:ticket_id>")
@login_required
def ticket_details(ticket_id):
    role = session["role"]
    username = session["username"]

    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Fetch ticket
    cur.execute("SELECT * FROM tickets WHERE id=?", (ticket_id,))
    ticket = cur.fetchone()

    if not ticket:
        conn.close()
        return "Ticket not found", 404

    assigned_to = ticket["assigned_to"]
    created_by = ticket["created_by"]

    # -------------------------
    # ACCESS CONTROL
    # -------------------------
    if role == "IT Staff" and assigned_to != username:
        return "Unauthorized — This ticket is not assigned to you.", 403

    if role == "Employee" and created_by != username:
        return "Unauthorized — You can only access your own tickets.", 403

    # -------------------------
    # COMMENTS VISIBILITY
    # -------------------------
    if role in ["Admin", "IT Staff"]:
        # IT + Admin see all (public + internal)
        cur.execute("""
            SELECT id, user_id, comment, created_at, is_internal
            FROM ticket_comments
            WHERE ticket_id=?
            ORDER BY created_at DESC
        """, (ticket_id,))
    else:
        # Employees see ONLY public notes
        cur.execute("""
            SELECT id, user_id, comment, created_at, is_internal
            FROM ticket_comments
            WHERE ticket_id=? AND is_internal=0
            ORDER BY created_at DESC
        """, (ticket_id,))

    comments = cur.fetchall()
    conn.close()

    return render_template("ticket_details.html",
                           ticket=ticket,
                           comments=comments,
                           role=role)


    # --- ACCESS CONTROL ---
    if role == "IT Staff" and assigned_to != username:
        return "Unauthorized", 403

    if role == "User" and created_by != username:
        return "Unauthorized", 403
    # -----------------------

    conn.close()
    return render_template("ticket_details.html", ticket=ticket)



# ------------------------------
# ADD A STAFF NOTE
# ------------------------------
@app.route("/add_note/<int:ticket_id>", methods=["POST"])
@login_required
def add_note(ticket_id):
    note = request.form["note"]
    username = session["username"]

    # internal note checkbox
    is_internal = 1 if request.form.get("is_internal") == "on" else 0

    # employees are NEVER allowed to add internal notes
    if session["role"] == "Employee":
        is_internal = 0

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO ticket_comments (ticket_id, user_id, comment, created_at, is_internal)
        VALUES (?, ?, ?, ?, ?)
    """, (ticket_id, username, note,
          datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
          is_internal))

    conn.commit()
    conn.close()

    return redirect(f"/ticket/{ticket_id}")


@app.route("/edit_note/<int:comment_id>", methods=["POST"])
@login_required
def edit_note(comment_id):
    new_text = request.form["new_text"]

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("""
        UPDATE ticket_comments
        SET comment=?
        WHERE id=?
    """, (new_text, comment_id))

    conn.commit()
    conn.close()

    return redirect(request.referrer)


@app.route("/delete_note/<int:comment_id>")
@login_required
def delete_note(comment_id):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("DELETE FROM ticket_comments WHERE id=?", (comment_id,))

    conn.commit()
    conn.close()
    return redirect(request.referrer)




@app.route("/knowledge")
def knowledge():
    categories = sorted(set(a["category"] for a in knowledge_base))
    return render_template("knowledge.html",
                           articles=knowledge_base,
                           categories=categories)

@app.route("/article/<int:article_id>")
def article(article_id):
    for a in knowledge_base:
        if a["id"] == article_id:
            return a
    return {"error": "Not found"}, 404


# -----------------------------------------
# ADMIN — VIEW ALL USERS
# -----------------------------------------
@app.route("/admin/users")
@login_required
def manage_users():
    if session["role"] != "Admin":
        return "Access Denied"

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    conn.close()

    return render_template("admin_users.html", users=users)


# -----------------------------------------
# ADMIN — ADD USER
# -----------------------------------------
@app.route("/admin/add_user", methods=["GET", "POST"])
@login_required
def add_user():
    if session["role"] != "Admin":
        return "Access Denied"

    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        role = request.form["role"]

        conn = sqlite3.connect("database.db")
        cur = conn.cursor()
        cur.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                    (username, password, role))
        conn.commit()
        conn.close()

        return redirect("/admin/users")

    return render_template("admin_add_user.html")


# -----------------------------------------
# ADMIN — EDIT USER ROLE / PASSWORD
# -----------------------------------------
@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
@login_required
def edit_user(user_id):
    if session["role"] != "Admin":
        return "Access Denied"

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    if request.method == "POST":
        role = request.form["role"]
        password = request.form["password"]

        if password:
            cur.execute("UPDATE users SET role=?, password=? WHERE id=?",
                        (role, password, user_id))
        else:
            cur.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))

        conn.commit()
        conn.close()
        return redirect("/admin/users")

    # Get selected user
    cur.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cur.fetchone()
    conn.close()

    return render_template("admin_edit_user.html", user=user)


# -----------------------------------------
# ADMIN — DELETE USER
# -----------------------------------------
@app.route("/admin/delete_user/<int:user_id>")
@login_required
def delete_user(user_id):
    if session["role"] != "Admin":
        return "Access Denied"

    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    cur.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

    return redirect("/admin/users")

@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    msg = data.get("message", "").lower()

    # SIMPLE RULE-BASED LOGIC
    if "password" in msg:
        reply = "To reset your password, go to Settings → Account → Reset Password."
    elif "wifi" in msg or "internet" in msg:
        reply = "If you are having internet issues, try reconnecting or restarting your router."
    elif "ticket" in msg:
        reply = "You can submit a new ticket from the sidebar under 'New Ticket'."
    elif "hello" in msg or "hi" in msg:
        reply = "Hello! How can I assist you today?"
    else:
        reply = "I'm not sure about that, but IT staff can help once you submit a ticket."

    return {"reply": reply}




if __name__ == "__main__":
    init_db()
    app.run(debug=True)
