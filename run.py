from app import app, socketio
import os

if __name__ == "__main__":
    port = int(os.environ.get('SERVER_PORT_DEV', 3000))
    socketio.run(app, debug=True, port=port)