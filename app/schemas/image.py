from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import Image

class ImageSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Image
        load_instance = True
        include_relationships = True
        include_fk = True

