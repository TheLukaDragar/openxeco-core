from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from webargs import fields, validate

from db.db import DB
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from utils.serializer import Serializer


class GetImages(MethodResource, Resource):

    def __init__(self, db: DB):
        self.db = db

    @log_request
    @doc(tags=['media'],
         description='Get images object from the media library',
         responses={
             "200": {},
         })
    @use_kwargs({
        'page': fields.Int(required=False, missing=1, validate=validate.Range(min=1)),
        'per_page': fields.Int(required=False, missing=50, validate=validate.Range(min=1, max=50)),
        'logo_only': fields.Bool(required=False),
        'is_in_generator': fields.Bool(required=False),
        'order': fields.Str(required=False, missing='desc', validate=lambda x: x in ['desc', 'asc']),
        'search': fields.Str(required=False),
    }, location="query")
    @jwt_required(fresh=True)
    @catch_exception
    def get(self, **kwargs):

        query = self.db.get_filtered_image_query(kwargs)
        paginate = query.paginate(kwargs['page'], kwargs['per_page'])
        images = Serializer.serialize(paginate.items, self.db.tables["Image"])

        return {
            "pagination": {
                "page": kwargs['page'],
                "pages": paginate.pages,
                "per_page": kwargs['per_page'],
                "total": paginate.total,
            },
            "items": images,
        }, "200 "
