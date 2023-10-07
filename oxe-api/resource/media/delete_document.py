from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from webargs import fields
import os

from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access
from config.config import DOCUMENT_FOLDER


class DeleteDocument(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['media'],
         description='Delete a document from the media library.',
         responses={
             "200": {},
         })
    @use_kwargs({
        'id': fields.Int(),
    })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def post(self, **kwargs):

        try:
            os.remove(os.path.join(DOCUMENT_FOLDER, str(kwargs["id"])))
        except FileNotFoundError:
            pass

        self.db.delete(self.db.tables["Document"], {"id": kwargs["id"]})

        return "", "200 "
