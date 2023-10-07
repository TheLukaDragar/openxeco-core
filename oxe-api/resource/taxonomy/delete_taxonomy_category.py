from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from webargs import fields

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access
from exception.object_not_found import ObjectNotFound


class DeleteTaxonomyCategory(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['taxonomy'],
         description='Delete a taxonomy category',
         responses={
             "200": {},
             "422": {"description": "Object not found"},
         })
    @use_kwargs({
        'category': fields.Str(),
    })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def post(self, **kwargs):

        values = self.db.get(self.db.tables["TaxonomyCategory"], {"name": kwargs["category"]})

        if len(values) > 0:
            self.db.delete(self.db.tables["TaxonomyCategory"], {"name": kwargs["category"]})
        else:
            raise ObjectNotFound

        return "", "200 "
