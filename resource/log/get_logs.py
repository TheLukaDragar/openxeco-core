from flask_restful import Resource
from flask_jwt_extended import jwt_required
from db.db import DB
from decorator.verify_admin_access import verify_admin_access
from utils.serializer import Serializer
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
import datetime
from flask import request


class GetLogs(Resource):

    def __init__(self, db: DB):
        self.db = db

    @log_request
    @jwt_required
    @verify_admin_access
    @catch_exception
    def get(self):

        filters = request.args.to_dict()
        today = datetime.date.today()
        two_weeks_ago = today - datetime.timedelta(days=14)

        query = self.db.session.query(self.db.tables["Log"]) \
            .filter(self.db.tables["Log"].sys_date > two_weeks_ago)

        if "resource" in filters and isinstance(filters["resource"], str):
            query = query.filter(self.db.tables["Log"].request.like(f"%{filters['resource']}%"))

        data = Serializer.serialize(query.all(), self.db.tables["Log"])

        return data, "200 "