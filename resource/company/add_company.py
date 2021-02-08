from flask_restful import Resource
from flask import request
from flask_jwt_extended import jwt_required
from decorator.log_request import log_request
from decorator.verify_payload import verify_payload
from decorator.verify_admin_access import verify_admin_access
from decorator.catch_exception import catch_exception


class AddCompany(Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @catch_exception
    @verify_payload(format=[
        {'field': 'name', 'type': str}
    ])
    @jwt_required
    @verify_admin_access
    def post(self):
        input_data = request.get_json()

        self.db.insert(input_data, self.db.tables["Company"])

        return "", "200 "
