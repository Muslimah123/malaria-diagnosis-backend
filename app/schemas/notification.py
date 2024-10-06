from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import Notification
from marshmallow import fields

class NotificationSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Notification
        load_instance = True
        include_relationships = True
        include_fk = True

    id = fields.Integer(dump_only=True)  # Exclude from input, only include in output
    created_at = fields.DateTime(dump_only=True)  # Exclude from input, only include in output
    updated_at = fields.DateTime(dump_only=True)  # Exclude from input, only include in output

    # You can add any additional fields or custom serialization logic here if needed
    user = fields.Nested('UserSchema', only=('user_id', 'username'), dump_only=True)  # Include minimal user info