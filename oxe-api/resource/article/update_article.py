from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from webargs import fields

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access


class UpdateArticle(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['article'],
         description='Update an article',
         responses={
             "200": {},
         })
    @use_kwargs({
        'id': fields.Int(),
        'handle': fields.Str(required=False, allow_none=True),
        'title': fields.Str(required=False, allow_none=True),
        'abstract': fields.Str(required=False, allow_none=True, validate=lambda x: x is None or len(x) <= 500),
        'publication_date': fields.Str(required=False, allow_none=True),
        'start_date': fields.Str(required=False, allow_none=True),
        'end_date': fields.Str(required=False, allow_none=True),
        'status': fields.Str(required=False, allow_none=True),
        'type': fields.Str(required=False, allow_none=True),
        'image': fields.Int(required=False, allow_none=True),
        'external_reference': fields.Str(required=False, allow_none=True),
        'link': fields.Str(required=False, allow_none=True),
    })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def post(self, **kwargs):

        self.db.merge(kwargs, self.db.tables["Article"])

        return "", "200 "
