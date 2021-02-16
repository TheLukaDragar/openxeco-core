from flask_restful import Resource
from flask_jwt_extended import jwt_required
from db.db import DB
from decorator.catch_exception import catch_exception
from decorator.verify_admin_access import verify_admin_access
from utils.serializer import Serializer
from decorator.log_request import log_request


class GetCompanyTaxonomy(Resource):

    def __init__(self, db: DB):
        self.db = db

    @log_request
    @catch_exception
    @jwt_required
    @verify_admin_access
    def get(self, id):

        ta = self.db.tables["TaxonomyAssignment"]
        data = Serializer.serialize(self.db.get(ta, {"company": id}), ta)

        return data, "200 "