from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import Metadata

class MetadataSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Metadata
        load_instance = True
        include_relationships = True
        include_fk = True
