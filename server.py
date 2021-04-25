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

def get_user(username, password):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username FROM `user` WHERE username=\'%s\' AND password=\'%s\'' % (username, password))
    row = cur.fetchone()
    conn.commit()
    conn.close()

    return {'id': row[0], 'username': row[1]} if row is not None else None

def get_user_uid(uid):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('SELECT id, username FROM `user` WHERE id=%d' % uid)
    row = cur.fetchone()
    conn.commit()
    conn.close()

    return {'id': row[0], 'username': row[1]}

def create_comment(uid, content):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('INSERT INTO `comment` VALUES (NULL, %d, \'%s\')' % (uid, content))
    row = cur.fetchone()
    conn.commit()
    conn.close()

    return row

def get_comments():
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('SELECT id, user_id, content FROM `comment` ORDER BY id DESC')
    rows = cur.fetchall()
    conn.commit()
    conn.close()

    return map(lambda row: {'id': row[0], 'user_id': row[1], 'content': row[2]}, rows)

def user_delete_comment_of_id(uid, tid):
    conn = connect_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM `comment` WHERE  user_id=%s AND id=%s' % (uid, tid))
    conn.commit()
    conn.close()

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
                <p>{{ line['content'] }}</p>
                {% if line['user_id'] == user['id'] %}
                <a href="/delete/comment/{{ line['id'] }}">Delete</a>
                {% endif %}
            </li>
            {% endfor %}
        </ul>
    </div>
    ''')
    return template.render(user=user, comments=comments)

@app.route('/')
def index():
    if 'uid' in session:
        return render_home_page(session['uid'])
    return redirect('/login')

@app.route('/xss', methods=['GET'])
def demo_xss():
    template = Template(
        """
        <div style="width: 400px; margin: 80px auto; ">
            <h4>Hello: {{ greeting }}</h4>
        </div>
        """
    )
    return template.render(greeting=request.args.get('greeting'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_login_page()
    elif request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username, password)
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
        create_comment(uid, request.form['content'])
    return redirect('/')

@app.route('/delete/comment/<tid>')
def delete_comment(tid):
    if 'uid' in session:
        user_delete_comment_of_id(session['uid'], tid)
    return redirect('/')

@app.route('/logout')
def logout():
    if 'uid' in session:
        session.pop('uid')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)


