from flask import Blueprint, request, jsonify,current_app
from flask_jwt_extended import jwt_required
from datetime import datetime

archived_data_bp = Blueprint('archived_data', __name__)

@archived_data_bp.route('/archived-data/<string:table_name>', methods=['GET'])
@jwt_required()
def get_archived_data(table_name):
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    
    if not start_date or not end_date:
        return jsonify({"error": "Start date and end date are required"}), 400
    
    try:
        start_date = datetime.strptime(start_date, '%Y-%m-%d')
        end_date = datetime.strptime(end_date, '%Y-%m-%d')
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    archived_data = current_app.data_archiver.retrieve_archived_data(start_date, end_date, table_name)
    
    return jsonify({"data": [dict(row) for row in archived_data]})