import base64
import io
import os
import traceback

from flask_apispec import MethodResource
from flask_apispec import use_kwargs, doc
from flask_jwt_extended import jwt_required
from flask_restful import Resource
from webargs import fields
from PIL import Image

from config.config import IMAGE_FOLDER
from decorator.catch_exception import catch_exception
from decorator.log_request import log_request
from decorator.verify_admin_access import verify_admin_access
from exception.error_while_saving_file import ErrorWhileSavingFile


class UploadLogo(MethodResource, Resource):

    db = None

    def __init__(self, db):
        self.db = db

    @log_request
    @doc(tags=['setting'],
         description='Upload logo of the project (overwrite if already exists). '
                     'Must be a PNG file. '
                     'Note: the media is then available via the resource public/get_image/logo.png',
         responses={
             "200": {},
             "500": {"description": "An error occurred while saving the file"},
         })
    @use_kwargs({
        'image': fields.Str(),
    })
    @jwt_required(fresh=True)
    @verify_admin_access
    @catch_exception
    def post(self, **kwargs):

        try:
            decoded_data = base64.b64decode(kwargs["image"].split(",")[-1])
            stream = io.BytesIO(decoded_data)
            image = Image.open(stream)
        except Exception:
            traceback.print_exc()
            return "", "422 Impossible to read the image"

        if image.format != 'PNG':
            return "", "422 Wrong image format. Must be a PNG file"

        try:
            f = open(os.path.join(IMAGE_FOLDER, "logo.png"), 'wb')
            f.write(decoded_data)
            f.close()
        except Exception:
            traceback.print_exc()
            raise ErrorWhileSavingFile

        return "", "200 "
