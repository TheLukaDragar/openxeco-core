from flask_restful import Resource
from flask import request
from flask_jwt_extended import jwt_required
from exception.object_not_found import ObjectNotFound
from decorator.verify_payload import verify_payload
from decorator.verify_admin_access import verify_admin_access
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request


class DeleteTaxonomyValue(Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @catch_exception
    @verify_payload(format=[
        {'field': 'category', 'type': str},
        {'field': 'name', 'type': str}
    ])
    @jwt_required
    @verify_admin_access
    def post(self):
        input_data = request.get_json()

        values = self.db.get(
            self.db.tables["TaxonomyValue"],
            {"name": input_data["name"], "category": input_data["category"]}
        )

        if len(values) == 0:
            raise ObjectNotFound
        else:
            self.db.delete(
                self.db.tables["TaxonomyValue"],
                {"name": input_data["name"], "category": input_data["category"]}
            )

        return "", "200 "