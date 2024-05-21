use std::str::FromStr;

use anyhow::{bail, Context, Result};
use argon2::Argon2;
use poem::{
    get, handler,
    web::{websocket::WebSocket, Data},
    Endpoint, IntoResponse, Request, Route,
};
use sea_orm::{DatabaseConnection, EntityTrait};
use uuid::Uuid;

use crate::{
    connection_manager::{ConnectionManagerHandle, IncomingDeviceConnection},
    device::DEVICE_KEY_HASH_LENGTH,
    entities::device,
};

const AUTH_HEADER: &str = "X-DeviceAuth";
const DEVICE_ID_HEADER: &str = "X-DeviceId";

#[handler]
async fn connect_device(
    db: Data<&DatabaseConnection>,
    cm: Data<&ConnectionManagerHandle>,
    ws: WebSocket,
    request: &Request,
) -> Result<impl IntoResponse> {
    let device_id: Uuid = Uuid::from_str(
        request
            .header(DEVICE_ID_HEADER)
            .context("No authentication")?,
    )
    .context("Invalid id format")?;
    let device_pass = request.header(AUTH_HEADER).context("No authentication")?;

    if let Some(device) = device::Entity::find_by_id(device_id.clone())
        .one(*db)
        .await?
    {
        let mut hashed_pass = [0u8; DEVICE_KEY_HASH_LENGTH];

        Argon2::default()
            .hash_password_into(
                device_pass.as_bytes(),
                &device.device_key_salt,
                &mut hashed_pass,
            )
            .context("Could not hash")?;

        let cm_handle = cm.clone();

        if hashed_pass == *device.device_key_hash {
            return Ok(ws.on_upgrade(move |socket| async move {
                let _ = cm_handle
                    .new_device(IncomingDeviceConnection {
                        id: device_id.clone(),
                        owner: device.owner.clone(),
                        name: device.device_name.clone(),
                        socket,
                    })
                    .await;
            }));
        }
    }

    bail!("Unauthenticated")
}

pub(crate) fn ws_routes() -> impl Endpoint {
    Route::new().at("/device", get(connect_device))
}
