from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask,jsonify, request
from flask_cors import CORS
from flask_mysqldb import MySQL
from dotenv import load_dotenv
import os, bcrypt,smtplib, ssl, secrets, datetime 


load_dotenv()

app = Flask(__name__)

app.config['MYSQL_HOST'] = os.getenv('DB_HOSTNAME')
app.config['MYSQL_USER'] = os.getenv('DB_USERNAME')
app.config['MYSQL_PASSWORD'] = os.getenv('DB_PASSWORD')
app.config['MYSQL_DB'] = os.getenv('DB_NAME')
mysql = MySQL(app)
CORS(app)

@app.route('/')
def hello_world():
    return secrets.token_urlsafe()

@app.route('/login', methods=['POST'])
def login_user():
    cur = mysql.connection.cursor()
    email = request.json['email']
    userPassword = request.json['password']
    userPasswordBytes = userPassword.encode('utf-8') 
    cur.execute('''SELECT password,is_auth,auth_token,auth_token_expiry_at FROM user WHERE email = %s''', (email,))
    login_data = cur.fetchone()
    
    if not login_data:
        cur.close()
        return jsonify({'message' : 'User not exist'})
    
    if login_data[1] == 0:
        currentDatetime = datetime.datetime.now()
        if (currentDatetime < login_data[3]):
            send_auth_email(login_data[2],email)
            return jsonify({'message' : 'User not authenticated. The email with authentication link has been resent on your email box.'})
        else:
            return jsonify({'message' : 'Authentication link expired. Please sign up again.'})
    
    cur.close()
    loginDataBytes = login_data[0].encode('utf-8')
    if bcrypt.checkpw(userPasswordBytes, loginDataBytes) :
        return jsonify({'message' : 'user_logged'})
    else:
        return jsonify({'message' : 'Password not valid'})

@app.route('/register', methods=['POST'])
def register_user():
    cur = mysql.connection.cursor()
    email = request.json['email']
    cur.execute('''SELECT is_auth FROM user WHERE email = %s''', (email,))
    user = cur.fetchone()
    if user:
        if user[0] == 0:
            return jsonify({'message' : 'user_not_auth'})
        else:
            return jsonify({'message' : 'user_already_exists'})
    
    password = request.json['password']
    pass_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    password_hash = bcrypt.hashpw(pass_bytes, salt)
    authToken = secrets.token_urlsafe()
    expiry_auth_token = datetime.datetime.now() + datetime.timedelta(hours=1)
    formatted_expiry_auth_token = expiry_auth_token.strftime('%Y-%m-%d %H:%M:%S')
    cur.execute('''INSERT INTO user (email, password, is_auth,auth_token,auth_token_expiry_at) VALUES (%s, %s,%s,%s,%s)''', (email, password_hash,0,authToken,formatted_expiry_auth_token))
    mysql.connection.commit()
    cur.close()

    return send_auth_email(authToken,email)

@app.route('/forgot', methods=['POST'])
def forgot_pass():
    cur = mysql.connection.cursor()
    token = request.json['token']
    new_password = request.json['newPassword']
    new_pass_bytes = new_password.encode('utf-8')
    salt = bcrypt.gensalt()
    new_password_hash = bcrypt.hashpw(new_pass_bytes, salt)
    cur.execute('''UPDATE user SET password=%s,forgot_pass_token=%s, forgot_token_expiry_at=%s WHERE forgot_pass_token = %s ''', (new_password_hash,None, None,token))
    mysql.connection.commit()
    cur.close()
    return jsonify({'message': 'Data updated successfully'})

@app.route('/checkForgotToken', methods=['POST'])
def check_forgot_token():
    cur = mysql.connection.cursor()
    tokenUser = request.json['token']
    current_datetime = datetime.datetime.now()
    cur.execute('''SELECT forgot_pass_token, forgot_token_expiry_at FROM user WHERE forgot_pass_token = %s''', (tokenUser,))
    token_data = cur.fetchone()
    cur.close()

    if not token_data:
        return jsonify({'message' : False})

    if tokenUser == token_data[0] and current_datetime < token_data[1]:
        return jsonify({'message' : True})
    else:
        return jsonify({'message' : False}) 

@app.route('/checkAuthToken', methods=['POST'])
def check_auth_token():
    cur = mysql.connection.cursor()
    authToken = request.json['token']
    current_datetime = datetime.datetime.now()
    cur.execute('''SELECT auth_token, auth_token_expiry_at FROM user WHERE auth_token = %s''', (authToken,))
    token_data = cur.fetchone()

    if not token_data:
        cur.close()
        return jsonify({'message' : False, 'reason' : 'User account already confirmed. Please sign in into account'})

    if authToken == token_data[0] and current_datetime < token_data[1]:
        cur.execute('''UPDATE user SET is_auth=%s, auth_token=%s, auth_token_expiry_at=%s WHERE auth_token = %s ''', (1,None,None,authToken))
        mysql.connection.commit()
        cur.close()
        return jsonify({'message' : True, 'reason' : 'User account successfully confirmed. Please sign in into account'})
    else:
        cur.close()
        return jsonify({'message' : False, 'reason': 'Link no longer valid. Please sign up to create account'}) 

@app.route('/sendForgotEmail', methods=['POST'])
def send_forgot_email():
    receiver_email = request.json['email']

    cur = mysql.connection.cursor()
    cur.execute('''SELECT forgot_pass_token, forgot_token_expiry_at FROM user WHERE email = %s''', (receiver_email,))
    user = cur.fetchone()
    cur.close()

    if not user:
        return jsonify({'message': 'user_not_exist'})
    
    if user[0] != None and user[1] != None:
        if datetime.datetime.now() < user[1]:
            return jsonify({'message': 'link_sent'})

    forgotToken = secrets.token_urlsafe()
    expiry_datetime_token = datetime.datetime.now() + datetime.timedelta(hours=1)
    formatted_expiry_datetime_token = expiry_datetime_token.strftime('%Y-%m-%d %H:%M:%S')
    cur = mysql.connection.cursor()
    cur.execute('''UPDATE user SET forgot_pass_token = %s, forgot_token_expiry_at = %s WHERE email = %s''', (forgotToken,formatted_expiry_datetime_token,receiver_email))
    mysql.connection.commit()
    cur.close()

    body = f"""<div style="font-family: system-ui, sans-serif, Arial; font-size: 14px; color: #333;">
<div style=" margin: auto; background-color: #fff;">
<div style="text-align: center; background-color: #333; padding: 14px;">&nbsp;</div>
<div style="padding: 14px;">
<h1 style="font-size: 22px; margin-bottom: 26px;">You have requested a password change</h1>
<p>We received a request to reset the password for your account. To proceed, please click the link below to create a new password:</p>
<p><a href="http://localhost:5173/resetPassword/{forgotToken}">http://localhost:5173/resetPassword/{forgotToken}</a></p>
<p>This link will expire in one hour.</p>
<p>If you didn't request this password reset, please ignore this email or let us know immediately. Your account remains secure.</p>
<p>Best regards,<br>FinApp Team</p>
</div>
</div>
<div style=" margin: auto;">
<p style="color: #999;">You received this email because you are registered with FinApp</p>
</div>
</div>"""

    return send_email(receiver_email,"Forgot password",body,True)

def send_auth_email(authToken, email):
    body = f"""<div style="font-family: system-ui, sans-serif, Arial; font-size: 14px; color: #333;">
<div style=" margin: auto; background-color: #fff;">
<div style="text-align: center; background-color: #333; padding: 14px;">&nbsp;</div>
<div style="padding: 14px;">
<h1 style="font-size: 22px; margin-bottom: 26px;">Your account has been created</h1>
<p>You created account for the FinApp. Please click the link below to confim an account:</p>
<p><a href="http://localhost:5173/confirmSignUp/{authToken}">http://localhost:5173/confirmSignUp/{authToken}</a></p>
<p>This link will expire in one hour.</p>
<p>If you didn't create this account, please ignore this email or let us know immediately.</p>
<p>Best regards,<br>FinApp Team</p>
</div>
</div>
<div style=" margin: auto;">
<p style="color: #999;">You received this email because you are registered with FinApp</p>
</div>
</div>"""
    send_email(email,"Please confirm your account",body,True)

    return jsonify({'message': 'user_registered'})

def send_email(to_email,subject,body,isHtml:bool):
    sender_email = os.getenv('GMAIL_SENDER')
    password = os.getenv('GMAIL_APP_PASSWORD')

    if isHtml == True:
        message = MIMEMultipart("alternative")
    else:
        message = MIMEText(body,"plain")
    
    message["Subject"] = subject
    message["From"] = sender_email
    message["To"] = to_email

    if isHtml == True:
        htmlMimeObj = MIMEText(body, "html")
        message.attach(htmlMimeObj)

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(os.getenv('SMTP_SERVER'), 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(
            sender_email, to_email, message.as_string()
        )
    return jsonify({'message': 'email_sent'})

if __name__ == '__main__':
    app.run(debug=True)
