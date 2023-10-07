from flask_apispec import MethodResource
from flask_apispec import doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource

from db.db import DB
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request


class GetUserEntityEnums(MethodResource, Resource):

    def __init__(self, db: DB):
        self.db = db

    @log_request
    @doc(tags=['user'],
         description='Get the enumerations of user entity assignment fields',
         responses={
             "200": {},
         })
    @jwt_required(fresh=True)
    @catch_exception
    def get(self):

        data = {
            "department": self.db.tables["UserEntityAssignment"].department.prop.columns[0].type.enums
        }

        return data, "200 "
