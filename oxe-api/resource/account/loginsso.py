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


class LoginSSO(MethodResource, Resource):

    db = None
    oidc = None  # Adding OIDC attribute

    def __init__(self, db, oidc):  # Modified constructor to accept OIDC object
        self.db = db
        self.oidc = oidc


    @log_request
    @doc(tags=['account'],
        description='Log in through Keycloak SSO',
        responses={
            "200": {},
            "401.a": {"description": "Unauthorized access"},
            "401.b": {"description": "The account is not active. Please contact the administrator"},
        })
    @catch_exception
    def post(self):

        if not self.oidc.user_loggedin:
            return self.oidc.require_login()
        else:
            # If already authenticated, direct to a safe location or inform the user
            return "Already logged in", 200


        # # Redirect user to Keycloak login page if not authenticated
        # if not self.oidc.user_loggedin:
        #     print("User not logged in redirecting to Keycloak")
        #     return self.oidc.require_login()

        # # Validate if the user is already authenticated by Keycloak
        # if self.oidc.user_loggedin:
        #     user_info = self.oidc.user_getinfo(['preferred_username', 'email', 'sub'])
        #     email = user_info['email']

        #     print("User logged in SSO with email: " + email)

        #     data = self.db.get(self.db.tables["User"], {"email": email})

        #     if not data:
        #         try:
        #             # Create the user with SSO-based details. No need for a password.
        #             print("Creating user with SSO since it does not exist already")
        #             user = self.db.insert({
        #                 "email": email,
        #                 "is_active": 1,
        #                 "password": "SSO",
        #                 "is_sso": 1,
        #             }, self.db.tables["User"])
        #         except IntegrityError as e:
        #             if "Duplicate entry" in str(e):
        #                 raise ObjectAlreadyExisting  # Your custom exception
        #             raise e


        #     data = self.db.get(self.db.tables["User"], {"email": email})


        #     if not data or not data[0].is_active:
        #         return "", "401 The account is not active. Please contact the administrator"

        #     access_token_expires = timedelta(days=1)
        #     refresh_token_expires = timedelta(days=365)

        #     access_token = create_access_token(identity=str(data[0].id), expires_delta=access_token_expires, fresh=True)
        #     refresh_token = create_refresh_token(identity=str(data[0].id), expires_delta=refresh_token_expires)

        #     response = make_response({
        #         "user": data[0].id,
        #     })

        #     now = datetime.now()

        #     response = set_cookie(request, response, "access_token_cookie", access_token, now + timedelta(days=1))
        #     response = set_cookie(request, response, "refresh_token_cookie", refresh_token, now + timedelta(days=365))

        #     return response

        # else:
        #     return "", "401 Unauthorized access"

    # @log_request
    # @doc(tags=['account'],
    #      description='Create an access and a refresh cookie by log in with an email and a password',
    #      responses={
    #          "200": {},
    #          "401.a": {"description": "Wrong email/password combination"},
    #          "401.b": {"description": "The account is not active. Please contact the administrator"},
    #      })
    # @use_kwargs({
    #     'email': fields.Str(),
    #     'password': fields.Str(),
    # })
    # @catch_exception
    # def post(self, **kwargs):

    #     data = self.db.get(self.db.tables["User"], {"email": kwargs["email"]})

    #     # If the user is not found, we simulate the whole process with a blank password.
    #     # This is done to limit the time discrepancy factor against the user enumeration exploit
    #     # CF: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

    #     password = data[0].password if len(data) > 0 else "Imp0ssiblePassword~~"

    #     if not check_password_hash(password, kwargs['password']):
    #         return "", "401 Wrong email/password combination"

    #     if not data[0].is_active:
    #         return "", "401 The account is not active. Please contact the administrator"

    #     access_token_expires = timedelta(days=1)
    #     refresh_token_expires = timedelta(days=365)
    #     access_token = create_access_token(identity=str(data[0].id), expires_delta=access_token_expires, fresh=True)
    #     refresh_token = create_refresh_token(identity=str(data[0].id), expires_delta=refresh_token_expires)

    #     response = make_response({
    #         "user": data[0].id,
    #     })

    #     now = datetime.now()

    #     response = set_cookie(request, response, "access_token_cookie", access_token, now + timedelta(days=1))
    #     response = set_cookie(request, response, "refresh_token_cookie", refresh_token, now + timedelta(days=365))

    #     return response
