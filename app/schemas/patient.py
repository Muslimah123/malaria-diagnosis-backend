from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import Patient
from marshmallow import fields


class PatientSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Patient
        load_instance = True
        include_relationships = True
        include_fk = True

    patient_id = fields.String(dump_only=True)  # Exclude from input, only include in output

