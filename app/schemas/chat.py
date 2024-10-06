from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from marshmallow import fields
from app.models import Chat
from app.schemas.message import MessageSchema  # Import MessageSchema here

# ChatSchema definition
class ChatSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Chat
        include_fk = True
    
    id = fields.Integer(dump_only=True)
    last_message_time = fields.DateTime(dump_only=True)
    created_at = fields.DateTime(dump_only=True)
    updated_at = fields.DateTime(dump_only=True)
    user = fields.Nested('UserSchema', only=('user_id', 'username'), dump_only=True)
    participant = fields.Nested('UserSchema', only=('user_id', 'username'), dump_only=True)
    messages = fields.Nested(MessageSchema, many=True, dump_only=True)  # Now this works
