from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from webargs import fields

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access


class UpdateRelationshipType(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['relationship'],
         description='Update a relationship type',
         responses={
             "200": {},
         })
    @use_kwargs({
        "id": fields.Int(required=True, allow_none=False),
        "name": fields.Str(required=False, allow_none=False),
        "is_directional": fields.Bool(required=False, allow_none=False),
    })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def post(self, **kwargs):

        self.db.merge(kwargs, self.db.tables["EntityRelationshipType"])

        return "", "200 "
