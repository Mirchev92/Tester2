from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def send_custom_email(app, recipient, subject, content):
    try:
        sender = app.config['MAIL_USERNAME']
        password = app.config['MAIL_PASSWORD']

        msg = MIMEMultipart()
        msg['From'] = sender
        msg['To'] = recipient
        msg['Subject'] = subject

        body = MIMEText(content, 'plain', 'utf-8')
        msg.attach(body)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender, password)
        text = msg.as_string()
        server.sendmail(sender, recipient, text)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False