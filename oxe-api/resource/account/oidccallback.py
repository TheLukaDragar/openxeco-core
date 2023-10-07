from datetime import datetime, timedelta

from flask import make_response, request
from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_bcrypt import check_password_hash
from flask_jwt_extended import create_access_token, create_refresh_token
from flask_restful import Resource
from webargs import fields
from exception.object_already_existing import ObjectAlreadyExisting
from sqlalchemy.exc import IntegrityError

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from utils.cookie import set_cookie

class OIDCCallback(MethodResource, Resource):

    db = None
    oidc = None

    def __init__(self, db, oidc):
        self.db = db
        self.oidc = oidc
        

    def get(self):
        if not self.oidc.user_loggedin:
            return "", "401 Unauthorized access"

        user_info = self.oidc.user_getinfo(['preferred_username', 'email', 'sub'])
        email = user_info['email']

        

        print("User logged in SSO with email: " + email)

        data = self.db.get(self.db.tables["User"], {"email": email})

        if not data:
            try:
                # Create the user with SSO-based details. No need for a password.
                print("Creating user with SSO since it does not exist already")
                user = self.db.insert({
                    "email": email,
                    "is_active": 1,
                    "password": "SSO",
                    "is_sso": 1,
                }, self.db.tables["User"])
            except IntegrityError as e:
                if "Duplicate entry" in str(e):
                    raise ObjectAlreadyExisting  # Your custom exception
                raise e


        access_token_expires = timedelta(days=1)
        refresh_token_expires = timedelta(days=365)
        access_token = create_access_token(identity=email, expires_delta=access_token_expires, fresh=True)
        refresh_token = create_refresh_token(identity=email, expires_delta=refresh_token_expires)

        response = make_response({"user": email})
        now = datetime.now()
        response = set_cookie(response, "access_token_cookie", access_token, now + timedelta(days=1))
        response = set_cookie(response, "refresh_token_cookie", refresh_token, now + timedelta(days=365))

        return response
