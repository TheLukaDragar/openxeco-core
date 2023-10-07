from flask import render_template
from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_bcrypt import generate_password_hash
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError
from webargs import fields

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from exception.object_already_existing import ObjectAlreadyExisting
from utils.mail import send_email
from utils.password import generate_password
from utils.regex import has_mail_format
from utils.env import get_community_portal_url


class CreateAccount(MethodResource, Resource):

    db = None
    mail = None

    def __init__(self, db, mail):
        self.db = db
        self.mail = mail

    @log_request
    @doc(tags=['account'],
         description='Create an account with the provided email as a user ID',
         responses={
             "200": {},
             "422.a": {"description": "The provided email does not have the right format"},
             "422.b": {"description": "An account already exists with this email address"},
             "422.c": {"description": "Object already existing"},
         })
    @use_kwargs({
        'email': fields.Str(),
        'entity': fields.Str(required=False, allow_none=True),
        'department': fields.Str(required=False, allow_none=True),
    })
    @catch_exception
    def post(self, **kwargs):

        email = kwargs["email"].lower()

        if not has_mail_format(email):
            return "", "422 The provided email does not have the right format"

        data = self.db.get(self.db.tables["User"], {"email": email})

        if len(data) > 0:
            return "", "422 An account already exists with this email address"

        # Create user

        generated_password = generate_password()

        try:
            user = self.db.insert({
                "email": email,
                "password": generate_password_hash(generated_password),
                "is_active": 1,
                "is_sso": 0,
            }, self.db.tables["User"])
        except IntegrityError as e:
            if "Duplicate entry" in str(e):
                raise ObjectAlreadyExisting
            raise e

        # Create the entity request if filled

        if "entity" in kwargs and kwargs["entity"] is not None \
           and "department" in kwargs and kwargs["department"] is not None:
            try:
                self.db.insert({
                    "user_id": user.id,
                    "request": "The user requests the access to the entity '"
                               + kwargs["entity"]
                               + "' with the following department: '"
                               + kwargs["department"]
                               + "'",
                    "type": "ENTITY ACCESS CLAIM",
                }, self.db.tables["UserRequest"])
            except IntegrityError as e:
                self.db.session.rollback()
                self.db.delete(self.db.tables["User"], {"id": user.id})
                raise e

        # Send email

        try:
            pj_settings = self.db.get(self.db.tables["Setting"], {"property": "PROJECT_NAME"})
            project_name = pj_settings[0].value if len(pj_settings) > 0 else ""

            send_email(self.mail,
                       subject=f"[{project_name}] New account",
                       recipients=[email],
                       html_body=render_template(
                           'account_creation.html',
                           url=get_community_portal_url() + "/login",
                           password=generated_password,
                           project_name=project_name)
                       )
        except Exception as e:
            self.db.session.rollback()
            self.db.delete(self.db.tables["User"], {"id": user.id})
            raise e

        return "", "200 "
