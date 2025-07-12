
from flask_socketio import SocketIO, join_room, leave_room
from flask import request
import logging

socketio = None

def init_socketio(app):
    global socketio
    socketio = SocketIO(app, cors_allowed_origins="http://localhost:3000")

    @socketio.on('connect')
    def handle_connect():
        client_id = request.sid
        logging.info(f"Client connected: {client_id}")
        socketio.emit('connection_response', {'data': 'Connected'}, to=client_id)

    @socketio.on('disconnect')
    def handle_disconnect():
        client_id = request.sid
        logging.info(f"Client disconnected: {client_id}")

    @socketio.on('join')
    def on_join(data):
        room = data.get('room')
        if not room:
            socketio.emit('error', {'message': 'Room ID missing'}, to=request.sid)
            logging.error("Attempted to join room without a room ID")
            return
        
        join_room(room)
        logging.info(f"Client {request.sid} joined room: {room}")
        socketio.emit('joined', {'room': room}, room=room)

    @socketio.on('leave')
    def on_leave(data):
        room = data.get('room')
        if not room:
            socketio.emit('error', {'message': 'Room ID missing'}, to=request.sid)
            logging.error("Attempted to leave room without a room ID")
            return

        leave_room(room)
        logging.info(f"Client {request.sid} left room: {room}")
        socketio.emit('left', {'room': room}, room=room)

    @socketio.on('join_user_room')
    def on_join_user_room(data):
        user_id = data.get('user_id')
        if not user_id:
            socketio.emit('error', {'message': 'User ID missing'}, to=request.sid)
            logging.error("Attempted to join user room without a user ID")
            return
        
        join_room(f"user_{user_id}")
        logging.info(f"Client {request.sid} joined user room: user_{user_id}")

    @socketio.on('join_chat')
    def on_join_chat(data):
        chat_id = data.get('chat_id')
        if not chat_id:
            socketio.emit('error', {'message': 'Chat ID missing'}, to=request.sid)
            logging.error("Attempted to join chat without a chat ID")
            return
        
        join_room(f"chat_{chat_id}")
        logging.info(f"Client {request.sid} joined chat room: chat_{chat_id}")

    @socketio.on_error()
    def handle_socket_error(e):
        logging.error(f"Socket error occurred: {str(e)}")

def send_processing_update(patient_id, image_id, status):
    if not socketio:
        raise RuntimeError("SocketIO is not initialized.")

    event_data = {
        'patient_id': patient_id,
        'status': status
    }
    
    if image_id:
        event_data['image_id'] = image_id
    
    socketio.emit('processing_update', event_data, room=f"patient_{patient_id}")
    logging.info(f"Sent processing update to patient {patient_id} with status: {status}, image_id: {image_id}")

def send_notification(user_id, notification):
    if not socketio:
        raise RuntimeError("SocketIO is not initialized.")

    socketio.emit('new_notification', notification, room=f"user_{user_id}")
    logging.info(f"Sent new notification to user {user_id}")

def send_new_message(chat_id, message):
    if not socketio:
        raise RuntimeError("SocketIO is not initialized.")

    socketio.emit('new_message', message, room=f"chat_{chat_id}")
    logging.info(f"Sent new message to chat {chat_id}")