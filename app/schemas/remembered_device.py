from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import RememberedDevice

class RememberedDeviceSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = RememberedDevice
        load_instance = True
        include_relationships = True
        include_fk = True