from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import BackupCode

class BackupCodeSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = BackupCode
        load_instance = True
        include_relationships = True
        include_fk = True