from flask_apispec import MethodResource
from flask_apispec import doc
from flask_jwt_extended import jwt_required, get_jwt_identity
from flask_restful import Resource
import random

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request


class GenerateMyUserHandle(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['private'],
         description='Update the user information related to the token. This is applicable to a limited'
                     ' number of fields',
         responses={
             "200": {},
         })
    @jwt_required(fresh=True)
    @catch_exception
    def post(self, **kwargs):

        kwargs["id"] = int(get_jwt_identity())

        words = open("template/bip39-words.txt").readlines()
        handle = "-".join(random.choices(words, k=4)).replace('\n', '').replace('\r', '')

        self.db.merge({"id": kwargs["id"], "handle": handle}, self.db.tables["User"])

        return "", "200 "
