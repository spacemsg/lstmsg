import eventlet
eventlet.monkey_patch()
from app import app, socketio

if __name__ == "__main__":
    socketio.run(app, host='26.216.5.64', port=443, debug=True)