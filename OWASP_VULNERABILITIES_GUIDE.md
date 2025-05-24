# Common Threat Vectors - Demo for CMSC 121: Web Programming

This demonstration application is designed to illustrate common web vulnerabilities in a simple Flask application. It's intended for educational purposes, particularly for students beginning to learn about web security and key concepts from the OWASP Top 10.

## Dependencies
Run the following command in cmd:

```
$pip install -r requirements.txt
```

## Usage
1. To use, create a .env file containing the key-value pair:
```
SECRET_KEY="<your_secret_key>"
```

2. Initialize the database by running the following code in Python Shell:
```
$python
>>> from app import init
>>> init()
>>> exit()
```

3. To run the web application, run the following command:
```
$python app.py
```

### Usage (Using CS50 IDE)
1. To use, create a .env file containing the key-value pair:
```
SECRET_KEY="<your_secret_key>"
```

2. Initialize the database by running the following code in Python Shell:
```
$python
>>> from app import init
>>> init()
>>> exit()
```

3. To run the web application, run the following command:
```
flask run
```

## Understanding Common Web Vulnerabilities

This section details the vulnerabilities demonstrated in this application.

### 1. SQL Injection (SQLi)

**What is SQL Injection?**
SQL Injection (SQLi) is a type of vulnerability where an attacker inserts malicious SQL code into input fields, which then gets executed as part of the database query. This can allow attackers to view, modify, or delete data in the database, and sometimes even gain control over the server.

**How it's demonstrated in this app:**
The vulnerability is shown in the login form (`/login`). When you attempt to log in, the application uses the `get_user_vulnerable_sqli` function in `app.py` to check your credentials. This function directly embeds your input into an SQL string, making it vulnerable.

*Vulnerable Code Snippet (`app.py` in `get_user_vulnerable_sqli`):*
```python
cur.execute('SELECT id, username FROM `user` WHERE username='%s' AND password='%s'' % (username, password))
```

**How to exploit it:**
To bypass the login, you can use a classic SQLi trick. Enter the following into both the username and password fields:
```
' OR '1'='1
```
This input changes the SQL query to something like:
```sql
SELECT id, username FROM `user` WHERE username='' OR '1'='1' AND password='' OR '1'='1'
```
Since `'1'='1'` is always true, the `WHERE` clause becomes true for one of the users, and you'll be logged in as that user (likely the first user in the database) without knowing their actual password.

**Mitigation: Parameterized Queries**
To prevent SQLi, you should use parameterized queries (also known as prepared statements). These ensure that user input is treated strictly as data, not as executable SQL code.

*Secure Code Snippet (`app.py` in `get_user_safe`):*
```python
cur.execute('SELECT id, username FROM `user` WHERE username=? AND password=?', (username, password))
```
In this secure version, the `?` are placeholders, and the database driver ensures that the `username` and `password` values are handled safely. The application includes `get_user_safe` and comments in the `/login` route showing how to switch to this safer version.

## 2. Cross-Site Scripting (XSS)

Cross-Site Scripting (XSS) is a common web vulnerability that occurs when an attacker manages to inject malicious code (usually JavaScript) into web pages viewed by other users. This code then runs in the victim's browser, allowing the attacker to perform actions on behalf of the user, steal sensitive information (like login tokens or cookies), or deface the website.

There are mainly two types of XSS attacks relevant to this demo: Reflected XSS and Stored XSS.

### a. Reflected XSS

**What is Reflected XSS?**
Reflected XSS happens when a web application takes some input from a user (often from a URL parameter) and immediately includes it in the HTML response sent back to that user without properly cleaning it. The malicious script is "reflected" off the web server to the user's browser. For an attack to be successful, the victim needs to click on a specially crafted link or submit a form that contains the malicious script.

**How it's demonstrated in this app:**
The vulnerability is present in the `/xss` route. The application takes a `greeting` parameter from the URL and directly embeds its value into the HTML page.

*Vulnerable Code Snippet (`app.py` in the `/xss` route):*
```python
@app.route('/xss', methods=['GET'])
def demo_xss():
    template = Template(
        """
        <div style="width: 400px; margin: 80px auto; ">
            <h4>Hello: {{ greeting }}</h4>
        </div>
        """
    )
    # The 'greeting' parameter is taken from the URL and rendered directly
    return template.render(greeting=request.args.get('greeting'))
```
In this code, `request.args.get('greeting')` fetches the text after `?greeting=` in the URL. This text is then passed directly into the HTML template.

**How to exploit it:**
An attacker can craft a URL that includes a script in the `greeting` parameter. For example:
`http://127.0.0.1:5000/xss?greeting=<script>alert('Reflected XSS!')</script>`

When a user visits this URL, their browser receives HTML that looks something like this:
```html
        <div style="width: 400px; margin: 80px auto; ">
            <h4>Hello: <script>alert('Reflected XSS!')</script></h4>
        </div>
```
The browser sees the `<script>` tag and executes the JavaScript code inside it, causing an alert box with the message "Reflected XSS!" to pop up. While an alert box itself is harmless, an attacker could use more complex scripts to steal cookies, redirect the user to a fake login page, or perform other malicious actions.

**Mitigation:**
The primary way to prevent Reflected XSS is through **output escaping** and **input sanitization**.
1.  **Output Escaping:** This means converting special characters in user input into their HTML entity equivalents before displaying them. For example, `<` becomes `&lt;`, `>` becomes `&gt;`, and `"` becomes `&quot;`. This makes the browser treat the input as text to be displayed, rather than as executable code.
    In Flask, Jinja2 templates (which are commonly used) often auto-escape content by default if you're rendering variables in HTML files. However, when constructing templates from strings or if auto-escaping is off, you must explicitly escape.
    *Secure Code Snippet (using Jinja2 explicit escaping):*
    ```python
    template = Template(
        """
        <div style="width: 400px; margin: 80px auto; ">
            <h4>Hello: {{ greeting | e }}</h4>
        </div>
        """
    )
    return template.render(greeting=request.args.get('greeting'))
    ```
    The `| e` filter in Jinja2 tells it to escape the `greeting` variable.
2.  **Input Sanitization/Validation:** This involves cleaning or rejecting user input before it's processed or stored. For example, if you expect a greeting to be plain text, you could remove any HTML tags. However, relying solely on input sanitization for XSS prevention is risky, as attackers can find ways to bypass filters. Output escaping is the more reliable defense.

### b. Stored XSS

**What is Stored XSS?**
Stored XSS (also known as Persistent XSS) is generally more dangerous than Reflected XSS. It occurs when an attacker injects a malicious script into a web application, and the application *stores* this script (e.g., in a database, a comment field, a user profile, etc.). When other users later view the page containing this stored script, their browsers execute it.

**How it's demonstrated in this app:**
This vulnerability is demonstrated through the comment feature.
1.  **Storing Malicious Input:** The `create_comment` function in `app.py` takes user input for comments and stores it directly in the database without any sanitization.
    *Vulnerable Code Snippet (`app.py` in `create_comment`):*
    ```python
    def create_comment(uid, content):
        conn = connect_db()
        cur = conn.cursor()
        # Vulnerable: Storing raw user input that might contain malicious scripts
        cur.execute('INSERT INTO `comment` VALUES (NULL, %d, \'%s\')' % (uid, content))
        conn.commit()
        conn.close()
    ```
2.  **Rendering Stored Content:** The `render_home_page` function retrieves comments from the database and displays them. One part of the template directly renders the comment content:
    *Vulnerable Rendering in `app.py` (within `render_home_page`'s template string):*
    ```python
    # ... inside the template string ...
                <p><strong>Vulnerable Rendering:</strong> {{ line['content'] }}</p>
    # ...
    ```
    If `line['content']` contains a script, it will be injected directly into the HTML page.

**How to exploit it:**
1.  Log in to the application (you might need to use the SQLi exploit if you don't have credentials).
2.  Go to the home page where comments are displayed and can be added.
3.  In the "Add comments" form, submit a comment containing a malicious script, for example:
    `<script>alert('Stored XSS! Your session cookies could be at risk.');</script>`
4.  Submit the comment.
5.  The application will save this script to the database. Now, every time any user (including yourself or an administrator) visits the home page, their browser will fetch and execute this script because it's part of the displayed comments. This could lead to stolen session cookies, redirection to malicious websites, or other attacks.

**Mitigation:**
The most effective way to prevent Stored XSS is **output escaping** when displaying user-supplied content.
1.  **Output Escaping:** Always escape data that originated from users before rendering it in HTML. The `render_home_page` function in `app.py` already includes an example of safe rendering:
    *Secure Code Snippet (in `render_home_page`'s template string):*
    ```python
    # ... inside the template string ...
                <p><strong>Safe (escaped) Rendering:</strong> {{ line['content'] | e }}</p>
    # ...
    ```
    The `| e` filter in Jinja2 is crucial here. It converts characters like `<` into `&lt;`, so the browser displays the script as harmless text instead of executing it. For example, `<script>alert(1)</script>` would be rendered as the literal text `&lt;script&gt;alert(1)&lt;/script&gt;` in the HTML source, which the browser will simply display.

While input sanitization (cleaning data before storing it) can be an additional layer of defense, output escaping is the most reliable and essential control against Stored XSS because it protects against scripts that might have bypassed input filters or were introduced through other means.

## 3. Insecure Direct Object References (IDOR)

Insecure Direct Object References (IDOR) are a type of **Broken Access Control** vulnerability. They happen when a web application allows a user to access resources (like files, data, or functions) directly by using an identifier (like an ID in the URL or a form parameter) that the user provides, *without checking if the user is actually authorized to access that specific resource*.

Imagine you have a key to your own apartment (Apartment #101). An IDOR vulnerability would be like if the building's main door system allowed you to use your key to open any apartment's door (e.g., Apartment #202) just by knowing its number, without verifying that the key belongs to that specific apartment.

IDOR vulnerabilities can lead to unauthorized viewing of sensitive data, modification of data belonging to other users, or even deletion of data.

### a. IDOR in Data Deletion (Comment Deletion)

**How it's demonstrated in this app:**
This application demonstrates an IDOR vulnerability in its comment deletion feature.
- The function `user_delete_comment_of_id_vulnerable(tid)` in `app.py` is responsible for deleting comments. It takes a comment ID (`tid`) and deletes it directly from the database without checking who owns the comment or who is requesting the deletion.
- The route `/delete/comment/<tid>` in `app.py` uses this function (or its fixed version). The comments in `app.py` guide you on how to switch to the vulnerable version for testing.

*Vulnerable Code Snippet (`app.py` in `user_delete_comment_of_id_vulnerable`):*
```python
def user_delete_comment_of_id_vulnerable(tid):
    conn = connect_db()
    cur = conn.cursor()
    # Vulnerable: Deletes comment by ID without checking ownership
    cur.execute('DELETE FROM `comment` WHERE id=%d' % tid)
    conn.commit()
    conn.close()
    return True # Simplified
```

**How to exploit it:**
Let's say:
1.  User A (logged in, with `uid=1`) posts a comment. This comment gets an ID, for example, `id=10`.
2.  User B (logged in, with `uid=2`) wants to delete User A's comment.
3.  If the vulnerable `user_delete_comment_of_id_vulnerable` function is active in the `/delete/comment/<tid>` route, User B can simply navigate to or craft a request to the URL: `/delete/comment/10`.
4.  The application will execute the vulnerable function, which deletes comment `id=10` without checking if User B is the owner. User A's comment is now deleted by User B.

**Mitigation: Ownership Check**
To prevent this, the application must verify that the user requesting the deletion is actually authorized to delete the specific comment.
- The function `user_delete_comment_of_id_fixed(uid, tid)` in `app.py` demonstrates this. It takes the current user's ID (`uid` from the session) and the comment ID (`tid`). It then checks if the `user_id` associated with the comment in the database matches the `uid` of the user making the request.

*Secure Code Snippet (`app.py` in `user_delete_comment_of_id_fixed`):*
```python
def user_delete_comment_of_id_fixed(uid, tid):
    conn = connect_db()
    cur = conn.cursor()
    # Fixed: Checks if the current user (uid) owns the comment (tid)
    cur.execute('SELECT user_id FROM `comment` WHERE id=%d' % tid)
    comment_owner_id = cur.fetchone()
    if comment_owner_id and comment_owner_id['user_id'] == uid:
        cur.execute('DELETE FROM `comment` WHERE id=%d AND user_id=%d' % (tid, uid))
        conn.commit()
        # ... (rest of the function) ...
    # ... (handle cases where user doesn't own the comment) ...
```
By ensuring the `user_id` in the `comment` table matches the logged-in user's `uid`, the application prevents users from deleting comments that don't belong to them.

### b. IDOR in Data Exposure (Viewing Comments)

**How it's demonstrated in this app:**
The application also shows a potential IDOR vulnerability in how individual comments can be viewed, if those comments were intended to be private or restricted.
- The function `get_comment_by_id_vulnerable(comment_id)` fetches any comment solely based on its `comment_id`.
- The route `/view_comment_vulnerable/<comment_id>` uses this function to display a comment.

*Vulnerable Code Snippet (`app.py` in `get_comment_by_id_vulnerable`):*
```python
def get_comment_by_id_vulnerable(comment_id):
    conn = connect_db()
    cur = conn.cursor()
    # Vulnerable: Fetches any comment by its ID, no ownership check
    cur.execute("SELECT * FROM comment WHERE id = %s", (comment_id,))
    comment = cur.fetchone()
    # ... (rest of the function) ...
    return comment
```

**How to exploit it:**
In the current demo, all comments are public, so this vulnerability doesn't directly expose private data. However, imagine a scenario where comments were meant to be private or only visible to certain users.
1.  User A posts a private comment, which gets `id=5`.
2.  An attacker (User B, or even an unauthenticated user) could try to guess or iterate through comment IDs by navigating to URLs like:
    - `/view_comment_vulnerable/1`
    - `/view_comment_vulnerable/2`
    - ...
    - `/view_comment_vulnerable/5`
3.  If the vulnerable function is in use, the attacker would be able to see User A's private comment (`id=5`) and any other comment whose ID they can guess, even if they are not authorized to view them.

**Mitigation: Authorization Check Before Displaying Data**
To fix this, the application should check if the logged-in user is authorized to view the requested comment before displaying it.
- The function `get_comment_by_id_fixed(user_id, comment_id)` (used by the `/view_comment_fixed/<comment_id>` route) demonstrates this by including a `user_id` check.

*Secure Code Snippet (`app.py` in `get_comment_by_id_fixed` - conceptual):*
```python
def get_comment_by_id_fixed(user_id, comment_id): # user_id is the logged-in user
    conn = connect_db()
    cur = conn.cursor()
    # Fixed: Fetches comment only if user_id matches (or other auth logic)
    # This example assumes a comment has a 'user_id' field linking to its owner.
    # For public comments, this check might be different or not needed,
    # but for private data, it's crucial.
    cur.execute("SELECT * FROM comment WHERE id = %s AND user_id = %s", (comment_id, user_id))
    comment = cur.fetchone()
    # ... (rest of the function) ...
    return comment
```
In a real application with private data, this function would ensure that `user_id` (the ID of the currently logged-in user) matches the `user_id` associated with the `comment_id` being requested. If they don't match, the comment would not be shown.

**Important Note for this Demo:** In this specific demo application, all comments are intended to be public. The `/view_comment_fixed/<comment_id>` route and `get_comment_by_id_fixed` function are provided to *illustrate the protection mechanism* you would use if comments *were* private. For public data, such a strict ownership check for viewing might not be necessary. However, the principle of checking authorization before accessing any resource is a core part of preventing IDOR.

## 4. Security Misconfiguration

Security Misconfiguration vulnerabilities occur when a system or application is not configured securely. This is a very broad category that can include many issues, such as:
-   Using default usernames and passwords for administrative accounts.
-   Enabling unnecessary features, especially debugging features, in a live production environment.
-   Displaying overly verbose or detailed error messages to users, which might reveal sensitive information about the system's inner workings.
-   Not "hardening" the application or the underlying server, which means not applying the latest security patches or not disabling unused services.

Essentially, it's about failing to implement all the necessary security controls or leaving systems in an insecure default state.

### a. Debug Mode in Production

A critical example of security misconfiguration, directly relevant to this Flask application, is running it with debug mode enabled in a live production environment.

In `app.py`, you'll find this line:
```python
if __name__ == '__main__':
    # WARNING: Only run in debug mode during development.
    # Never run in debug mode in a production environment.
    # Debug mode can expose sensitive information and allow arbitrary code execution.
    app.run(debug=True)
```
The `app.run(debug=True)` setting is invaluable for development because it provides helpful feedback and tools. However, it's extremely dangerous in production.

**Risks associated with `debug=True` in production:**

1.  **Exposure of Sensitive Information:**
    When an error occurs in a Flask application running with `debug=True`, it doesn't just show a generic error page. Instead, it can display a detailed traceback directly in the user's browser. This traceback includes:
    *   Large parts of your application's source code.
    *   The structure of your application (how different files and functions are connected).
    *   The values of local variables, which might include sensitive data like database queries, configuration settings (e.g., API keys, database credentials if not handled carefully), or user information.
    An attacker can intentionally trigger errors to view this information, learning a lot about your application and potentially finding other vulnerabilities.

2.  **Potential for Arbitrary Code Execution:**
    The Werkzeug debugger (which Flask uses) provides an interactive console in the browser when an error occurs in debug mode. This console is protected by a PIN. However:
    *   If this PIN is weak, guessed, leaked, or bypassed due to other misconfigurations, an attacker can gain access to this console.
    *   Once in the console, the attacker can execute arbitrary Python code on your server. This means they can do almost anything: access or delete files, install malware, connect to databases, or take over the server completely.
    This is a very severe risk.

### b. Best Practices / Mitigation

*   **Development vs. Production:** The `debug=True` setting is strictly for development purposes. It should **never** be active in a production environment.
*   **Disable Debug Mode:** For production, ensure your application is run with debug mode turned off (e.g., `app.run(debug=False)` if you were using the development server, but see the next point).
*   **Use a Production-Grade WSGI Server:** Flask's built-in server (`app.run()`) is a development server and is not designed for production use. It's not very efficient, secure, or robust for handling real-world traffic. For deploying Flask applications (or any Python web application), you should use a production-grade WSGI (Web Server Gateway Interface) server like:
    *   Gunicorn
    *   uWSGI
    These servers are designed for performance, stability, and security. They are typically run behind a reverse proxy like Nginx or Apache, which can handle tasks like SSL termination, serving static files, and load balancing. When using a production WSGI server, the `debug` flag is typically managed through environment variables or configuration files specific to that server or your deployment process, ensuring it's off for production.

## 5. Vulnerable and Outdated Components

**What are Vulnerable and Outdated Components?**
This vulnerability category refers to the risk of using software components in your application that are old, no longer supported by their developers, or, most importantly, have publicly known security weaknesses (vulnerabilities). These components can include:
-   Software libraries (like `Flask`, `Jinja2`, or `sqlite3` in Python)
-   Web frameworks themselves (like Flask)
-   Server-side software (like the Python interpreter or the operating system)
-   Other modules or plugins your application relies on.

Think of it like building a house with bricks that you know are cracked or using a lock on your door that everyone knows how to pick.

**What are the risks?**
-   **Active Exploitation:** Attackers actively scan the internet for systems using components with known, well-documented vulnerabilities. Exploits for these are often readily available.
-   **System Compromise:** A single vulnerable component can be enough for an attacker to take over your entire application, steal sensitive data, or even gain control of the server it runs on. For example, a flaw in an old version of a web framework might allow an attacker to execute arbitrary code on your server.
-   **Chain Reactions:** Sometimes, one vulnerable component can be used to exploit other parts of your system.
-   **Examples:**
    *   Using an old version of Flask that has a known remote code execution (RCE) vulnerability.
    *   Employing a data visualization library that has a documented XSS flaw.
    *   Running your application on an operating system version that is no longer receiving security patches.

**How does this relate to this project?**
In this Python Flask project, our dependencies (the external libraries and framework we use) are listed in the `requirements.txt` file. This file specifies the versions of libraries like:
-   `Flask` (the web framework itself)
-   `Jinja2` (the templating engine)
-   `Werkzeug` (a WSGI utility library used by Flask)
-   And potentially others as a project grows.

If, for instance, the specific version of `Flask` listed in `requirements.txt` (e.g., `Flask==1.0.0`) had a critical security flaw discovered and publicly announced, then this entire web application would be vulnerable just by using that outdated version. Attackers knowing about the flaw in `Flask==1.0.0` could specifically target applications using it.

**Mitigation: How to protect your application**
Preventing issues with vulnerable components is an ongoing process:
1.  **Keep Components Up-to-Date:**
    *   Regularly check for and apply security patches and updates for all components. This includes the web framework (Flask), all libraries listed in `requirements.txt`, the Python interpreter, your database system, and the server's operating system.
    *   For Python projects, you can use commands like `pip list --outdated` to see which of your dependencies have newer versions available. Then, update them carefully (e.g., `pip install -U <library-name>`).
2.  **Use Official Sources:**
    *   Always download libraries and software from official repositories (like PyPI for Python packages - `pip install` does this by default) or directly from the vendor's website. This helps avoid using components that have been tampered with by attackers.
3.  **Monitor for Vulnerabilities:**
    *   Use tools and services that can automatically scan your project's dependencies for known vulnerabilities. Examples include:
        *   GitHub's Dependabot (often enabled by default for repositories on GitHub)
        *   Tools like `safety` (for Python: `pip install safety && safety check -r requirements.txt`)
        *   OWASP Dependency-Check
    *   Subscribe to security mailing lists or bulletins related to the software you use.
4.  **Remove Unused Components:**
    *   If you're no longer using a particular library or component, uninstall it from your project and server. This reduces the "attack surface" – fewer components mean fewer potential vulnerabilities.
    *   Regularly review your `requirements.txt` to ensure all listed dependencies are still necessary.
5.  **Understand Component Risks:**
    *   Before adding a new library, do a quick check for its maintenance status and any known security issues. Prefer well-maintained libraries from reputable sources.

## 6. Conclusion and Further Learning

Understanding and mitigating common web vulnerabilities is a crucial skill for anyone involved in web development, whether you're building a small personal project or a large-scale application. As you've seen in this guide, a single oversight can potentially lead to serious security issues.

The vulnerabilities we've explored here—SQL Injection (SQLi), Cross-Site Scripting (XSS), Insecure Direct Object References (IDOR), Security Misconfiguration, and using Vulnerable and Outdated Components—are some of the most common and impactful threats that web applications face. However, the world of web security is vast and constantly evolving.

We strongly encourage you to continue your learning journey in web application security. A fantastic resource for staying updated on the most critical security risks is the **OWASP Top 10 Project**. OWASP (Open Web Application Security Project) is a non-profit foundation that works to improve software security, and their Top 10 list is a globally recognized awareness document for developers and web application security.

-   **Explore the OWASP Top 10:** [https://owasp.org/www-project-top-ten/](https://owasp.org/www-project-top-ten/)

Remember, writing secure code is not a one-time task but an ongoing practice. It requires continuous learning, vigilance, and a proactive mindset to anticipate and defend against potential threats. Keep exploring, keep questioning, and keep building more secure web applications!
