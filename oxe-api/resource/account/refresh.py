import datetime

from flask import make_response, request
from flask_apispec import MethodResource
from flask_apispec import doc
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_restful import Resource

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from utils.cookie import set_cookie


class Refresh(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['account'],
         description='Request the token',
         responses={
             "200": {},
         })
    @jwt_required(fresh=True)
    @catch_exception
    def post(self):


        user_id = get_jwt_identity()
        user_data = self.db.get(self.db.tables["User"], {"id": user_id})

        if user_data[0].is_sso:  # Assuming 'is_sso' is the new field in your User table
            # Redirect to SSO login or handle according to your SSO policy
            #TODO: Handle SSO refresh token
            pass

        access_token_expires = datetime.timedelta(days=1)
        access_token = create_access_token(identity=get_jwt_identity(), expires_delta=access_token_expires, fresh=True)

        response = make_response({
            "user": get_jwt_identity(),
        })

        now = datetime.datetime.now()

        response = set_cookie(request, response, "access_token_cookie", access_token, now + datetime.timedelta(days=1))

        return response
