from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from app.models import DiagnosisResult

class DiagnosisResultSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = DiagnosisResult
        load_instance = True
        include_relationships = True
        include_fk = True
