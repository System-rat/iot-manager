use poem::web::websocket::WebSocketStream;
use tokio::sync::mpsc::{Receiver, Sender};
use uuid::Uuid;

struct IncomingDeviceConnection {
    name: String,
    id: Uuid,
    socker: WebSocketStream,
}

struct IncomingUserConnection {
    id: Uuid,
    username: String,
    socket: WebSocketStream,
}

enum ConnectionManagerMessage {
    NewClient(IncomingUserConnection),
    NewDevice(IncomingDeviceConnection),
    DeviceDisconnected(Uuid),
    UserDisconnected(Uuid),
}

struct DeviceHandle {
    incoming_commands: Receiver<()>,
    telemetry_sink: Sender<()>,
    manager: ConnectionManagerHandle,
}

struct UserHandle {
    incoming_telemetry: Receiver<()>,
    command_sink: Sender<()>,
    manager: ConnectionManagerHandle,
}

#[derive(Clone)]
struct ConnectionManagerHandle {
    command_sender: Sender<ConnectionManagerMessage>,
}

