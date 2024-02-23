from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file
import mysql.connector
from mysql.connector import Error
from flask_bcrypt import Bcrypt
import jwt
import datetime
from werkzeug.utils import secure_filename
from mysql.connector import Binary
import os  # Import the os module

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'my secret key'

# Additional configuration for file upload to a separate database
db_config = {
   'host': 'localhost',
   'user': 'root',
   'password': 'Msia@444',
   'database': 'amigos_project'
}



def connect_to_mysql():
   try:
      conn = mysql.connector.connect(**db_config)
      if conn.is_connected():
         print(f'Connected to MySQL database')
         return conn
   except Error as e:
      print(e)


def close_connection(conn):
   if conn.is_connected():
      conn.close()
      print('Connection to MySQL database closed')



# def create_users_table():
#     with conn.cursor() as cursor:
#         cursor.execute("""
#             CREATE TABLE IF NOT EXISTS users_details (
#                 userid INT AUTO_INCREMENT PRIMARY KEY,
#                 username VARCHAR(255) COLLATE utf8mb4_bin NOT NULL UNIQUE,
#                 email VARCHAR(255) UNIQUE,
#                 fullname VARCHAR(255) NOT NULL,
#                 password VARCHAR(255) NOT NULL UNIQUE
#             )
#         """)
#         connection.commit()

# def create_images_table():
#     with connection.cursor() as cursor:
#         cursor.execute("""
#             CREATE TABLE IF NOT EXISTS images_table  (
#                imageid INT PRIMARYKEY AUTO_INCREMENT,
#                userid INT NOT ,
#               image LONGBLOB ,        
#             )
#         """)
#         connection.commit()
def create_users_table():
    conn = connect_to_mysql()
    if conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users_details (
                        userid INT AUTO_INCREMENT PRIMARY KEY,
                        username VARCHAR(255) COLLATE utf8mb4_bin NOT NULL UNIQUE,
                        email VARCHAR(255) UNIQUE,
                        fullname VARCHAR(255) NOT NULL,
                        password VARCHAR(255) NOT NULL
                    )
                """)
                conn.commit()
        finally:
            close_connection(conn)

# Create images table
def create_images_table():
    conn = connect_to_mysql()
    if conn:
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS images_table (
                        imageid INT AUTO_INCREMENT PRIMARY KEY,
                        userid INT NOT NULL,
                        image LONGBLOB
                    )
                """)
                conn.commit()
        finally:
            close_connection(conn)



def generate_token(username):
    expiry_date = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    payload = {'username': username, 'exp': expiry_date}
    token = jwt.encode(payload, app.secret_key, algorithm='HS256')
    return token   

# Function to verify JWT token
def verify_token(token):
    try:
        payload = jwt.decode(token,app.secret_key, algorithms=['HS256'])
        return payload['username']
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None     


@app.route('/')
def index():
   return render_template('index.html')




def save_files_to_database(userid, file_names):
   try:
      conn = mysql.connector.connect(**db_config)
      print("Connected to MySQL")
      cursor = conn.cursor()

      for file_name in file_names:
         with open(file_name, 'rb') as file:
               image_data = file.read()
               # Insert each image separately
               cursor.execute('''
                  INSERT INTO images_table (userid, image)
                  VALUES (%s, %s)
               ''', (userid, Binary(image_data)))
               conn.commit()


      flash('Files saved to the database successfully', 'success')

   except Error as e:
      flash(f'Error saving files to the database: {str(e)}', 'error')

   finally:
      cursor.close()
      close_connection(conn)



# @app.route('/')
# def index():
#    return render_template('index.html')

@app.route('/signup', methods=['POST','GET'])
def signup():
    error = None
    # error_mssg = None
    conn = connect_to_mysql()
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        fullname = request.form['fullname']
        password = request.form['password']

        # Check if the username or email already exists
        cursor.execute("SELECT * FROM users_details WHERE username = %s OR email = %s", (username, email))
        existing_user = cursor.fetchone()
        if existing_user:
            error = "User with this username or email already exists."
            return render_template('index.html', error=error)  # Render the signup page with the error message
        else:
            # Hash the password
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Insert the new user into the database
            insert_query = "INSERT INTO users_details (username, email, fullname, password) VALUES (%s, %s, %s, %s)"
            user_data = (username, email, fullname, hashed_password)
            cursor.execute(insert_query, user_data)
            conn.commit()

            close_connection(conn)
            return redirect(url_for('mult_image'))  # Redirect to the success route

    return render_template('index.html', error=error)

@app.route('/login', methods=['POST', 'GET'])
def login():
    error_msg = None
    
    conn = connect_to_mysql()
    cursor = conn.cursor(dictionary=True)

    username = request.form.get('username','')
    password = request.form.get('password','')

    cursor.execute("SELECT * FROM users_details WHERE username = %s", (username,))
    user = cursor.fetchone()

    if user and bcrypt.check_password_hash(user['password'], password):
        token = generate_token(username)
        conn.close()
        return redirect(url_for('user_profile', username=username, token=token))
    else:
        error_msg = 'Invalid username or password'
        return render_template('index.html', error_msg=error_msg)
        


def connectt_to_mysql():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='Msia@444',
        database='amigos_project'
    )
@app.route('/user_profile/<username>', methods=['POST', 'GET'])
def user_profile(username):
    token = request.args.get('token')
    verified_username = verify_token(token)
    
    if verified_username == username:
        conn = connectt_to_mysql()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users_details WHERE username = %s", (verified_username,))
        user = cursor.fetchone()
        
        if user:
            conn.close()
            return render_template('user_page.html', user=user)
        else:
            return "User not found."
    else:
        return "Unauthorized access."




# Route to serve the images from the temporary folder
@app.route('/uploads/<filename>')
def uploaded_file(filename):
   return send_file(os.path.join(app.root_path, 'static', filename))


@app.route('/upload_files', methods=['POST'])
def upload_files():
 # Retrieve userid from the session
   userid = session.get('userid')
   if not userid:
      flash('User not logged in', 'error')
      return redirect(url_for('login'))  
    
   image_files = request.files.getlist('image')

   if image_files:
      file_names = []

      for image_file in image_files:
         file_name = secure_filename(image_file.filename)
         image_file.save(file_name)
         file_names.append(file_name)

      save_files_to_database(userid, file_names)

      flash('Files uploaded and saved to the database successfully', 'success')

   return 'Files uploaded successfully'


@app.route('/multImage')
def mult_image():
    return render_template('multImag.html')



@app.route('/video')
def video():
    return render_template('video.html')












if __name__ == '__main__':
    create_users_table()  # Create the users table if it doesn't exist
    create_images_table()
    
    app.run(debug=True, port=5007)
