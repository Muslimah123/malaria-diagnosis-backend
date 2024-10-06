from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import  Visit

class VisitSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Visit
        load_instance = True
        include_relationships = True
        include_fk = True