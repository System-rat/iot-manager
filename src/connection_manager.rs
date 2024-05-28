use std::sync::Arc;

use anyhow::{bail, Result};
use futures::{SinkExt, StreamExt};
use poem::web::websocket::{Message, WebSocketStream};
use tokio::sync::{
    mpsc::{channel, Receiver, Sender},
    Mutex,
};
use uuid::Uuid;

pub(crate) struct IncomingDeviceConnection {
    pub(crate) name: String,
    pub(crate) id: Uuid,
    pub(crate) owner: Uuid,
    pub(crate) socket: WebSocketStream,
}

pub(crate) struct IncomingUserConnection {
    pub(crate) id: Uuid,
    pub(crate) devices: Vec<Uuid>,
    pub(crate) username: String,
    pub(crate) socket: WebSocketStream,
}

enum ConnectionManagerMessage {
    NewClient(IncomingUserConnection),
    NewDevice(IncomingDeviceConnection),
    DeviceDisconnected(Uuid),
    UserDisconnected(Uuid),
}

struct DeviceHandle {
    command_sink: Sender<String>,
    manager: ConnectionManagerHandle,
    id: Uuid,
}

struct UserHandle {
    telemetry_sink: Sender<String>,
    manager: ConnectionManagerHandle,
    id: Uuid,
}

#[derive(Clone)]
pub(crate) struct ConnectionManagerHandle {
    command_sender: Sender<ConnectionManagerMessage>,
}

impl ConnectionManagerHandle {
    pub async fn new_device(&self, device: IncomingDeviceConnection) -> Result<()> {
        if self.command_sender.send(ConnectionManagerMessage::NewDevice(device)).await.is_err() {
            bail!("Error during send");
        }

        Ok(())
    }

    pub async fn new_client(&self, client: IncomingUserConnection) -> Result<()> {
        if self.command_sender.send(ConnectionManagerMessage::NewClient(client)).await.is_err() {
            bail!("Error during send");
        }

        Ok(())
    }
}

pub(crate) fn create_manager() -> ConnectionManagerHandle {
    let (cm_tx, mut cm_rx) = channel::<ConnectionManagerMessage>(100);

    let devices: Arc<Mutex<Vec<DeviceHandle>>> = Arc::new(Mutex::new(vec![]));
    let users: Arc<Mutex<Vec<UserHandle>>> = Arc::new(Mutex::new(vec![]));
    let cm = ConnectionManagerHandle {
        command_sender: cm_tx.clone(),
    };
    let cm_clone = cm.clone();
    let cm_user_clone = cm.clone();

    tokio::spawn(async move {
        while let Some(incomming) = cm_rx.recv().await {
            match incomming {
                ConnectionManagerMessage::NewDevice(dev) => {
                    let device_owner = dev.owner.clone();
                    let (device_ingress, mut rx) = create_device_ingestion(dev, cm_clone.clone());
                    devices.lock().await.push(device_ingress);
                    let users_arc = users.clone();

                    tokio::spawn(async move {
                        while let Some(msg) = rx.recv().await {
                            let usrs = users_arc.lock().await;
                            for usr in usrs.iter().filter(|u| u.id == device_owner) {
                                let _ = usr.telemetry_sink.send(msg.clone()).await;
                            }
                        }
                    });
                }
                ConnectionManagerMessage::NewClient(client) => {
                    let user_devices = client.devices.clone();
                    let (user_control, mut rx) = create_user_control(client, cm_user_clone.clone());
                    users.lock().await.push(user_control);
                    let devices_arc = devices.clone();

                    tokio::spawn(async move {
                        while let Some(msg) = rx.recv().await {
                            let dvcs = devices_arc.lock().await;
                            for dev in dvcs.iter().filter(|d| user_devices.contains(&d.id)) {
                                let _ = dev.command_sink.send(msg.clone()).await;
                            }
                        }
                    });
                }
                ConnectionManagerMessage::DeviceDisconnected(id) => {
                    let mut devs = devices.lock().await;
                    if let Some(pos) = devs.iter().position(|d| d.id == id) {
                        devs.remove(pos);
                    }
                }
                ConnectionManagerMessage::UserDisconnected(id) => {
                    let mut usrs = users.lock().await;
                    if let Some(pos) = usrs.iter().position(|u| u.id == id) {
                        usrs.remove(pos);
                    }
                }
            }
        }
    });

    cm
}

fn create_device_ingestion(
    device: IncomingDeviceConnection,
    handle: ConnectionManagerHandle,
) -> (DeviceHandle, Receiver<String>) {
    let (device_telemetry_tx, device_telemetry_rx) = channel(100);
    let (device_commands_tx, mut device_commands_rx) = channel(100);

    let (mut ws_tx, mut ws_rx) = device.socket.split();

    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            if let Ok(msg) = msg {
                if let Message::Text(str) = msg {
                    let _ = device_telemetry_tx.send(str).await;
                }
            } else {
                break;
            }
        }
    });

    tokio::spawn(async move {
        while let Some(msg) = device_commands_rx.recv().await {
            if ws_tx.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    (
        DeviceHandle {
            id: device.id,
            manager: handle,
            command_sink: device_commands_tx,
        },
        device_telemetry_rx,
    )
}

fn create_user_control(
    user: IncomingUserConnection,
    handle: ConnectionManagerHandle,
) -> (UserHandle, Receiver<String>) {
    let (user_telemetry_tx, mut user_telemetry_rx) = channel(100);
    let (user_commands_tx, user_commands_rx) = channel(100);

    let (mut ws_tx, mut ws_rx) = user.socket.split();

    tokio::spawn(async move {
        while let Some(msg) = ws_rx.next().await {
            if let Ok(msg) = msg {
                if let Message::Text(str) = msg {
                    let _ = user_commands_tx.send(str).await;
                }
            } else {
                break;
            }
        }
    });

    tokio::spawn(async move {
        while let Some(msg) = user_telemetry_rx.recv().await {
            if ws_tx.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });

    (
        UserHandle {
            id: user.id,
            manager: handle,
            telemetry_sink: user_telemetry_tx,
        },
        user_commands_rx,
    )
}
