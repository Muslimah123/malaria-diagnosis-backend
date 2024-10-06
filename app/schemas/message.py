from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import fields
from app.models import  Message


class MessageSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Message
        include_fk = True
    
    id = fields.Integer(dump_only=True)
    timestamp = fields.DateTime(dump_only=True)
    sender = fields.Nested('UserSchema', only=('user_id', 'username'), dump_only=True)