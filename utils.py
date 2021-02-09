from flask import session

def clear_user_session():
    if "user_info" in session:
        del session["user_info"]

    if "token" in session:
        del session["token"]
