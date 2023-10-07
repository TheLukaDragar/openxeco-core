from flask_apispec import MethodResource
from flask_apispec import doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource

from db.db import DB
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access
from utils.serializer import Serializer


class GetUserGroupAssignments(MethodResource, Resource):

    def __init__(self, db: DB):
        self.db = db

    @log_request
    @doc(tags=['user'],
         description='Get user group assignments',
         responses={
             "200": {},
         })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def get(self):

        data = self.db.get(self.db.tables["UserGroupAssignment"])
        data = Serializer.serialize(data, self.db.tables["UserGroupAssignment"])

        return data, "200 "
