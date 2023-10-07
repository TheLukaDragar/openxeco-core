from flask_apispec import MethodResource
from flask_apispec import doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource

from db.db import DB
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access


class GetNotifications(MethodResource, Resource):

    def __init__(self, db: DB):
        self.db = db

    @log_request
    @doc(tags=['notification'],
         description='Get number of requests with a NEW status and number of data control result',
         responses={
             "200": {},
         })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def get(self):

        active_form_ids = [r[0] for r in self.db.session
                           .query(self.db.tables["Form"])
                           .with_entities(self.db.tables["Form"].id)
                           .filter(self.db.tables["Form"].status == "ACTIVE")
                           .all()]

        data = {
            "new_requests": self.db.session
                                .query(self.db.tables["UserRequest"])
                                .filter(self.db.tables["UserRequest"].status == "NEW")
                                .count(),
            "data_control": self.db.session
                                .query(self.db.tables["DataControl"])
                                .count(),
            "articles_under_review": self.db.session
                                         .query(self.db.tables["Article"])
                                         .filter(self.db.tables["Article"].status == "UNDER REVIEW")
                                         .count(),
            "form_responses": self.db.session
                                .query(self.db.tables["FormQuestion"], self.db.tables["FormAnswer"])
                                .filter(self.db.tables["FormQuestion"].form_id.in_(active_form_ids))
                                .join(self.db.tables["FormQuestion"],
                                      self.db.tables["FormQuestion"].id
                                      == self.db.tables["FormAnswer"].form_question_id)
                                .group_by(self.db.tables["FormQuestion"].form_id, self.db.tables["FormAnswer"].user_id)
                                .count(),
        }

        return data, "200 "
