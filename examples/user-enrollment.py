from lldap import LLDAPManager
from getpass import getpass
import string
import random
import smtplib
from email.mime.text import MIMEText

password_input=getpass("Enter user creators password: ")  # hidden input prompt


manager = LLDAPManager(
    http_url = "http://localhost:17170",
    username = "admin",
    password = password_input,
    base_dn = "dc=example,dc=com",
    ldap_server = "ldap://localhost:3890",
)


new_user_id = input("\nEnter new user ID to onboard: ")
new_user_email = input("Enter new user email: ")
new_user_first = input("Enter new user first name: ")
new_user_lastname = input("Enter new user last name: ")
new_user_displayname = new_user_first + " " + new_user_lastname

manager.create_user(
    new_user_id,
    new_user_email,
    new_user_displayname,
    new_user_first,
    new_user_lastname
)

manager.add_user_to_group(new_user_id, manager.get_group_id("BasicUserGroup"))


## Generate random password
new_user_password = "".join(random.choices(string.ascii_letters + string.digits, k=12))

manager.set_password(new_user_id, new_user_password)

enrollment_message = f"""
Dear {new_user_displayname} 
Welcome as new user on example.com
Your new account has the following credentials:
Username: {new_user_id}
Temporary Password: {new_user_password}

Please go to auth.example.com to login and set you password.

Best regards, Server adminsitrator

"""

# Update these SMTP settings for your environment.
SMTP_HOST = "smtp.example.com"
SMTP_PORT = 587
SMTP_USERNAME = "no-reply@example.com"
SMTP_PASSWORD = "your-smtp-password"
SMTP_FROM = "no-reply@example.com"

msg = MIMEText(enrollment_message)
msg["Subject"] = "Your new account on example.com"
msg["From"] = SMTP_FROM
msg["To"] = new_user_email


with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
    smtp.ehlo()
    smtp.starttls()
    smtp.login(SMTP_USERNAME, SMTP_PASSWORD)
    smtp.send_message(msg)
print(f"Enrollment email sent to {new_user_email}.")

manager.close()




