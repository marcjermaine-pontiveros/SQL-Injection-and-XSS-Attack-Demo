import os
import sqlite3

from flask import Flask, redirect, request, session
from jinja2 import Template

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY")

DATABASE_PATH = os.path.join(os.path.dirname(__file__), 'database.db')



def connect_db():
    '''
    Connects to an sqlite3 database
    '''
    return sqlite3.connect(DATABASE_PATH)

def create_tables():
    '''
    Create user tables
    '''
    conn = connect_db()
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS user(id INTEGER PRIMARY KEY AUTOINCREMENT,
        username VARCHAR(32),
        password VARCHAR(32))
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS comment(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        content TEXT,
        FOREIGN KEY (`user_id`) REFERENCES `user`(`id`))
        """
    )
    conn.commit()
    conn.close()

def init_data():
    users = [
        ('marc', '123456'),
        ('jermaine', '654321')
    ]

    comments = [
        ('1', 'Oh, hello there'),
        ('2', 'some ads'),
        ('2', 'im jermaine'),
        ('2', 'comments')
    ]

    conn = connect_db()
    cur = conn.cursor()
    cur.executemany('INSERT INTO `user` VALUES(NULL,?,?)', users)
    cur.executemany('INSERT INTO `comment` VALUES(NULL,?,?)', comments)
    conn.commit()
    conn.close()

def init():
    print("Creating database tables...")
    create_tables()
    print("Initializing data...")
    init_data()
    print("Init complete!")

# --- SQL Injection (SQLi) ---
# SQL Injection Explained (As per OWASP_VULNERABILITIES_GUIDE.md):
# SQLi is a vulnerability where an attacker inserts malicious SQL code into input fields,
# which then gets executed as part of the database query. This can allow attackers
# to view, modify, or delete data, and sometimes gain server control.
#
# How this function (`get_user_vulnerable_sqli`) is vulnerable:
# It uses Python's string formatting (`%s`) to directly embed `username` and `password`
# into the SQL query string. This means if an attacker inputs special SQL characters,
# they can alter the query's logic.
#
# Example of an SQLi exploit:
#   Username: ' OR '1'='1
#   Password: ' OR '1'='1
# The SQL query becomes:
#   SELECT id, username FROM `user` WHERE username='' OR '1'='1' AND password='' OR '1'='1'
# Since '1'='1' is always true, the condition becomes true for a user (likely the first one),
# bypassing the password check and granting unauthorized access.
def get_user_vulnerable_sqli(username, password):
    conn = connect_db()
    cur = conn.cursor()
    # VULNERABLE: User input is directly formatted into the SQL query string.
    # This is dangerous because special characters in username/password can change the query's meaning.
    cur.execute('SELECT id, username FROM `user` WHERE username=\'%s\' AND password=\'%s\'' % (username, password))
    row = cur.fetchone()
    # Note: conn.commit() is not needed for SELECT statements.
    conn.close()

    return {'id': row[0], 'username': row[1]} if row is not None else None

# How parameterized queries (prepared statements) prevent SQLi:
# Parameterized queries send the SQL query structure to the database server first,
# and then separately send the user-supplied data as parameters.
# The database engine then treats this user data strictly as data, NOT as executable SQL code.
# Even if an attacker tries to inject SQL commands (e.g., ' OR '1'='1'), these are treated
# as literal string values to be searched for, not as SQL logic to be executed.
# This effectively neutralizes the SQL injection attempt.
def get_user_safe(username, password):
    conn = connect_db()
    cur = conn.cursor()
    # SAFE: Using parameterized query. The '?' are placeholders.
    # The database driver ensures that the (username, password) values are treated as data, not SQL code.
    cur.execute('SELECT id, username FROM `user` WHERE username=? AND password=?', (username, password))
    row = cur.fetchone()
    # Note: conn.commit() is not needed for SELECT statements.
    conn.close()

    return {'id': row[0], 'username': row[1]} if row is not None else None

def get_user_uid(uid):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username FROM `user` WHERE id=%d' % uid)
    row = cur.fetchone()
    conn.commit() # This commit is actually not necessary for a SELECT query.
    conn.close()

    return {'id': row[0], 'username': row[1]}

# --- Stored Cross-Site Scripting (XSS) ---
# What Stored XSS is (As per OWASP_VULNERABILITIES_GUIDE.md):
# Stored XSS occurs when an application receives data containing malicious scripts
# (e.g., from a user comment) and stores this un-escaped data on the server (e.g., in a database).
# When this stored data is later retrieved and displayed to other users without proper HTML escaping,
# the malicious script executes in their browsers.
#
# How this function (`create_comment`) contributes to Stored XSS:
# This function takes `content` (e.g., a user's comment) and directly inserts it
# into the database using string formatting. If this `content` contains malicious
# script tags (e.g., <script>alert('Stored XSS!')</script>), that script will be stored as is.
# When this comment is later displayed by `render_home_page` without escaping,
# the script will execute in the browsers of users viewing the page.
def create_comment(uid, content):
    conn = connect_db()
    cur = conn.cursor()
    # VULNERABLE: Storing raw user input (content) directly into the database.
    # If 'content' contains JavaScript, it gets saved and can be executed later.
    cur.execute('INSERT INTO `comment` VALUES (NULL, %d, \'%s\')' % (uid, content))
    row = cur.fetchone() # This will be None for an INSERT statement.
    conn.commit()
    conn.close()

    return row # Returning row here is not typical for an insert, will be None.

def get_comments():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('SELECT id, user_id, content FROM `comment` ORDER BY id DESC')
    rows = cur.fetchall()
    conn.commit() # This commit is actually not necessary for a SELECT query.
    conn.close()

    return map(lambda row: {'id': row[0], 'user_id': row[1], 'content': row[2]}, rows)

# --- IDOR (Insecure Direct Object References) Demonstrations ---
# What is IDOR? (As per OWASP_VULNERABILITIES_GUIDE.md)
# IDOR occurs when an application uses user-supplied input (like an ID in a URL)
# to access objects (e.g., database records, files) directly, without verifying
# if the logged-in user is actually authorized to access that specific object.
# Attackers can manipulate these IDs to access or modify data not belonging to them.

# IDOR Vulnerability (Comment Deletion)
# This function is vulnerable because it deletes a comment based *only* on the
# comment ID (`tid`) provided by the user. It does *not* check if the comment
# actually belongs to the currently logged-in user making the request.
# Any authenticated user can delete any comment if they know its ID.
def user_delete_comment_of_id_vulnerable(tid):
    conn = connect_db()
    cur = conn.cursor()
    # VULNERABLE: Deletes comment by its ID (`tid`) without checking ownership.
    # An attacker (User B) can delete a comment belonging to User A by providing its `tid`.
    cur.execute('DELETE FROM `comment` WHERE id=%s' % tid)
    conn.commit()
    conn.close()

# Fixed Comment Deletion (Checks Ownership)
# This function is secure against this IDOR because it requires both the comment ID (`tid`)
# AND the user ID (`uid`) of the currently logged-in user (obtained from the session).
# The SQL query ensures that a comment is deleted only if its `id` matches `tid` AND
# its `user_id` (the owner of the comment) matches `uid`.
def user_delete_comment_of_id_fixed(uid, tid):
    conn = connect_db()
    cur = conn.cursor()
    # FIXED: Deletes comment only if `user_id` matches the logged-in user's `uid`.
    # This prevents User B from deleting User A's comment.
    cur.execute('DELETE FROM `comment` WHERE user_id=%s AND id=%s' % (uid, tid))
    conn.commit()
    conn.close()

# IDOR Vulnerability (Data Exposure - Viewing Comments)
# This function is vulnerable because it fetches a comment based *only* on its `comment_id`.
# It does not check if the logged-in user (or any user) should have access to this comment.
# If comments were intended to be private or restricted, this function would allow any user
# to view any comment if they can guess its ID.
def get_comment_by_id_vulnerable(comment_id):
    conn = connect_db()
    cur = conn.cursor()
    # VULNERABLE: Fetches any comment by its ID, without checking if the current user is authorized to view it.
    # If comments were private, this would expose them to unauthorized users.
    cur.execute('SELECT id, user_id, content FROM `comment` WHERE id=%s' % comment_id)
    row = cur.fetchone()
    # Note: conn.commit() is not needed for SELECT statements.
    conn.close()
    return {'id': row[0], 'user_id': row[1], 'content': row[2]} if row else None

# Fixed Comment Viewing (Hypothetical - if comments were private or user-specific)
# This function demonstrates how to prevent IDOR for data exposure. It checks if the
# `user_id` associated with the comment matches the `user_id` of the logged-in user.
# For this specific demo application, all comments are public. However, this function
# illustrates the access control pattern you would use if comments had privacy settings.
def get_comment_by_id_fixed(user_id, comment_id):
    conn = connect_db()
    cur = conn.cursor()
    # FIXED: Fetches comment only if its `user_id` matches the `user_id` of the requester.
    # This is a pattern for restricting access to objects based on ownership.
    # For truly public comments, this specific check might not be needed, but the principle applies
    # to any data that should not be universally accessible.
    cur.execute('SELECT id, user_id, content FROM `comment` WHERE id=%s AND user_id=%s', (comment_id, user_id))
    row = cur.fetchone()
    # Note: conn.commit() is not needed for SELECT statements.
    conn.close()
    return {'id': row[0], 'user_id': row[1], 'content': row[2]} if row else None


def render_login_page():
    return '''
    <form method="POST" style="margin: 60px auto; width: 140px;">
        <p><input name="username" type="text" /></p>
        <p><input name="password" type="password" /></p>
        <p><input value="Login" type="submit" /></p>
    </form>
    '''

def render_home_page(uid):
    user = get_user_uid(uid)
    comments = get_comments()
    # Stored XSS Demonstration: Rendering stored content
    # How this template contributes to Stored XSS:
    # The `line['content']` variable holds comment data fetched from the database.
    # In the "Vulnerable Rendering" part, `{{ line['content'] }}` directly inserts this
    # data into the HTML. If a comment stored in the database (via `create_comment`)
    # contains a malicious script (e.g., "<script>alert('XSS')</script>"), that script
    # will be rendered as actual HTML and JavaScript, causing it to execute in the browser
    # of anyone viewing the page.
    #
    # Example of a Stored XSS payload (submitted as a comment via the form):
    #   <script>document.body.innerHTML = '<h1>XSS Attack!</h1>'</script>
    #
    # Mitigation through Output Escaping:
    # The "Safe (escaped) Rendering" part uses `{{ line['content'] | e }}`.
    # The `| e` is a Jinja2 filter that performs HTML escaping. It converts special HTML
    # characters like '<' into '&lt;', '>' into '&gt;', '&' into '&amp;', etc.
    # This makes the browser treat the malicious script as literal text to be displayed,
    # rather than as executable code, thus neutralizing the Stored XSS attack.
    template = Template('''
    <div style="width: 400px; margin: 80px auto; ">
        <h4>I am: {{ user['username'] }}</h4>
        <form method="POST" action="/create_comments">
            Add comments:
            <input type="text" name="content" />
            <input type="submit" value="Submit" />
        </form>
        <ul style="border-top: 1px solid #ccc;">
            {% for line in comments %}
            <li style="border-top: 1px solid #efefef;">
                <p><strong>Vulnerable Rendering:</strong> {{ line['content'] }}</p>
                <p><strong>Safe (escaped) Rendering:</strong> {{ line['content'] | e }}</p>
                {% if line['user_id'] == user['id'] %}
                <a href="/delete/comment/{{ line['id'] }}">Delete</a>
                {% endif %}
            </li>
            {% endfor %}
        </ul>
    </div>
    ''')
    # Educational Note: While Flask's default Jinja2 setup auto-escapes content in .html files,
    # using `Template()` with a string as done here might not always have auto-escaping enabled by default
    # depending on the broader Flask configuration. Explicitly using the `|e` filter is a
    # robust way to ensure escaping and clearly demonstrates the security measure.
    return template.render(user=user, comments=comments)

@app.route('/')
def index():
    if 'uid' in session:
        return render_home_page(session['uid'])
    return redirect('/login')

# --- Reflected Cross-Site Scripting (XSS) ---
@app.route('/xss', methods=['GET'])
def demo_xss():
    # What Reflected XSS is (As per OWASP_VULNERABILITIES_GUIDE.md):
    # Reflected XSS occurs when an application takes user input from an HTTP request
    # (typically a URL parameter) and immediately includes that input in the HTML response
    # sent back to the *same user*, without proper sanitization or escaping.
    # The malicious script is thus "reflected" off the web server to the user's browser.
    #
    # How this route is vulnerable:
    # 1. The `greeting` parameter is fetched from the URL: `request.args.get('greeting')`.
    # 2. This `greeting` value is then directly embedded into the HTML template string
    #    using `{{ greeting }}` without any escaping.
    # If an attacker crafts a URL with a malicious script in the `greeting` parameter and
    # tricks a user into clicking it, that script will be embedded in the HTML response
    # and executed by that user's browser.
    #
    # Example of a URL triggering Reflected XSS:
    #   http://127.0.0.1:5000/xss?greeting=<script>alert('Reflected XSS by ' + document.domain)</script>
    # When a user visits this URL, the script executes, showing an alert.
    template = Template(
        """
        <div style="width: 400px; margin: 80px auto; ">
            <h4>Hello: {{ greeting }}</h4>
        </div>
        """
    )
    # VULNERABLE RENDERING: The `greeting` variable is rendered without escaping.
    # If `greeting` contains HTML/JS, it will be executed by the browser.
    #
    # Mitigation: Use Jinja2's `|e` filter for explicit escaping: {{ greeting | e }}
    # This would convert <script> to &lt;script&gt;, rendering it harmlessly as text.
    # While Flask's default Jinja2 environment often auto-escapes in .html files,
    # explicit escaping is crucial when building templates from strings or for clarity.
    return template.render(greeting=request.args.get('greeting'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_login_page()
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # --- SQL Injection Vulnerability Point ---
        # The line below uses the VULNERABLE `get_user_vulnerable_sqli` function.
        # This is for demonstration purposes to show how SQLi can be exploited.
        # An attacker can use specially crafted username/password like "' OR '1'='1"
        # to bypass authentication.
        #
        # To use the SAFE version, which prevents SQLi using parameterized queries,
        # change the line below to:
        # user = get_user_safe(username, password)
        user = get_user_vulnerable_sqli(username, password)
        if user is not None:
            print("Authenticated!")
            session['uid'] = user['id']
            return redirect('/')
        else:
            return redirect('/login')

@app.route('/create_comments', methods=['POST'])
def create_comment_path():
    if 'uid' in session:
        uid = session['uid']
        # This is where Stored XSS begins: user input is passed to `create_comment`.
        # If `create_comment` stores it raw, and `render_home_page` displays it raw, XSS occurs.
        create_comment(uid, request.form['content'])
    return redirect('/')

@app.route('/delete/comment/<tid>')
def delete_comment(tid):
    if 'uid' in session:
        # --- IDOR Vulnerability Demonstration (Comment Deletion) ---
        # This route demonstrates how IDOR can be exploited for unauthorized deletion.
        # The choice of function below determines if it's vulnerable or fixed.

        # VULNERABLE IDOR SCENARIO:
        # If `user_delete_comment_of_id_vulnerable(tid)` is called:
        #   - It only uses `tid` (the comment ID, a direct object reference from the URL).
        #   - It does NOT check if the logged-in user (`session['uid']`) owns this comment.
        #   - Result: Any logged-in user can delete any comment if they know its ID,
        #             e.g., by crafting a URL like /delete/comment/123 where 123 is another user's comment.
        #
        # UNCOMMENT THE LINE BELOW TO TEST THE VULNERABLE (IDOR) VERSION:
        # user_delete_comment_of_id_vulnerable(tid)
        # print(f"VULNERABLE: Attempting to delete comment {tid} without ownership check.")


        # FIXED (SECURE) SCENARIO:
        # If `user_delete_comment_of_id_fixed(session['uid'], tid)` is called:
        #   - It uses both `tid` AND `session['uid']` (the current user's ID).
        #   - The function `user_delete_comment_of_id_fixed` ensures the comment's `user_id`
        #     matches `session['uid]` before deleting.
        #   - Result: Users can only delete their own comments. IDOR is prevented.
        user_delete_comment_of_id_fixed(session['uid'], tid)
        # print(f"FIXED: Attempting to delete comment {tid} with ownership check for user {session['uid']}.")
    return redirect('/')

# --- IDOR (Data Exposure) Vulnerability Demonstration Route ---
@app.route('/view_comment_vulnerable/<comment_id>')
def view_comment_vulnerable_route(comment_id):
    # This route demonstrates IDOR for data exposure.
    # It calls `get_comment_by_id_vulnerable(comment_id)`, which fetches any comment
    # based *only* on its `comment_id` (the direct object reference from the URL).
    # It does *not* check if the current user (logged in or anonymous) is authorized to view it.
    #
    # If comments were intended to be private or contained sensitive information:
    # An attacker could iterate through comment IDs (e.g., /view_comment_vulnerable/1,
    # /view_comment_vulnerable/2, ...) to view data they shouldn't see.
    comment = get_comment_by_id_vulnerable(comment_id)
    if comment:
        return f"<h1>Viewing Comment (Potentially Insecure - IDOR Vulnerable)</h1><p><b>ID:</b> {comment['id']}</p><p><b>User ID:</b> {comment['user_id']}</p><p><b>Content:</b> {comment['content']}</p>"
    return "Comment not found.", 404 # Or "Access Denied" if a real system had mixed public/private

# --- IDOR (Data Exposure) Fixed Demonstration Route ---
@app.route('/view_comment_fixed/<comment_id>')
def view_comment_fixed_route(comment_id):
    # This route demonstrates the fix for IDOR in data exposure, assuming comments
    # are user-specific and should only be viewed by their owners.
    # It uses `get_comment_by_id_fixed(session['uid'], comment_id)`.
    # This function will only return a comment if the `comment_id` exists AND
    # its `user_id` matches the `session['uid']` of the currently logged-in user.
    #
    # Note: For this demo app, comments are generally public on the homepage.
    # This route specifically shows how you *would* protect them if they were private.
    if 'uid' not in session:
        return "Please log in to view specific comments.", 403 # User must be logged in

    comment = get_comment_by_id_fixed(session['uid'], comment_id)
    if comment:
        return f"<h1>Viewing Comment (Secure - IDOR Protected)</h1><p><b>ID:</b> {comment['id']}</p><p><b>User ID:</b> {comment['user_id']}</p><p><b>Content:</b> {comment['content']}</p>"
    return "Comment not found or you do not have permission to view this comment.", 404


@app.route('/logout')
def logout():
    if 'uid' in session:
        session.pop('uid')
    return redirect('/login')

# --- Security Misconfiguration Demonstration ---
# What is Security Misconfiguration? (As per OWASP_VULNERABILITIES_GUIDE.md)
# Security Misconfiguration vulnerabilities arise when a system or application component
# is not configured securely. This is a broad category, including issues like:
# - Using default credentials.
# - Enabling unnecessary features (like debug modes in production).
# - Displaying overly verbose error messages that leak internal information.
# - Not applying security patches or "hardening" the server and application.
#
# The `app.run(debug=True)` line below is a classic example of a security misconfiguration
# IF this application were deployed to a live ("production") server.
#
# Why `debug=True` is a critical risk in a production environment:
# 1.  Exposure of Sensitive Information:
#     When an error occurs in a Flask app with `debug=True`, it typically displays a
#     detailed traceback and an interactive debugger directly in the browser. This can reveal:
#     - Large parts of your application's source code.
#     - The internal structure of your project.
#     - Values of local variables during the error, which might include database details,
#       API keys, or other sensitive data.
#     An attacker can intentionally trigger errors to gather this information.
#
# 2.  Potential for Arbitrary Code Execution:
#     The Werkzeug debugger (which Flask uses) provides an interactive console in the browser
#     when an error occurs in debug mode. This console is protected by a PIN. However:
#     - If this PIN is weak, guessed, leaked, or if there's a vulnerability allowing PIN bypass,
#       an attacker can gain access to this console.
#     - Once in the console, the attacker can execute arbitrary Python code on your server,
#       effectively giving them full control over the application and potentially the server.
#
# Best Practices / Mitigation:
# - `debug=True` is invaluable for development due to its detailed error feedback and
#   features like auto-reloading.
# - However, for production deployments, debug mode MUST ALWAYS be set to `False`.
# - Production Flask applications should be run using a production-grade WSGI (Web Server
#   Gateway Interface) server such as Gunicorn or uWSGI, often behind a reverse proxy
#   like Nginx. These servers are designed for security, performance, and stability,
#   unlike Flask's built-in development server (`app.run()`).

if __name__ == '__main__':
    # WARNING: `debug=True` is for development ONLY.
    # For a production environment, this must be `debug=False`.
    # More appropriately, a production-grade WSGI server (like Gunicorn) should be used
    # to run the application, and Flask's built-in server should not be used.
    app.run(debug=True)


