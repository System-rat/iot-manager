use anyhow::{bail, Context, Result};
use argon2::Argon2;
use poem::{
    get, handler,
    session::Session,
    web::{websocket::WebSocket, Data, Query},
    Endpoint, EndpointExt, IntoResponse, Route,
};
use sea_orm::{DatabaseConnection, EntityTrait, ModelTrait};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    auth::{RequireAuth, AUTH_COOKIE_ID_FIELD},
    connection_manager::{
        ConnectionManagerHandle, IncomingDeviceConnection, IncomingUserConnection,
    },
    device::DEVICE_KEY_HASH_LENGTH,
    entities::{device, user},
};

#[derive(Deserialize)]
struct DeviceAuth {
    device_id: Uuid,
    auth_password: String
}

#[handler]
async fn connect_device(
    db: Data<&DatabaseConnection>,
    cm: Data<&ConnectionManagerHandle>,
    ws: WebSocket,
    Query(device_auth): Query<DeviceAuth>,
) -> Result<impl IntoResponse> {
    if let Some(device) = device::Entity::find_by_id(device_auth.device_id)
        .one(*db)
        .await?
    {
        let mut hashed_pass = [0u8; DEVICE_KEY_HASH_LENGTH];

        Argon2::default()
            .hash_password_into(
                device_auth.auth_password.as_bytes(),
                &device.device_key_salt,
                &mut hashed_pass,
            )
            .context("Could not hash")?;

        let cm_handle = cm.clone();

        if hashed_pass == *device.device_key_hash {
            return Ok(ws.on_upgrade(move |socket| async move {
                let _ = cm_handle
                    .new_device(IncomingDeviceConnection {
                        id: device_auth.device_id,
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

#[handler]
async fn connect_client(
    session: &Session,
    db: Data<&DatabaseConnection>,
    cm: Data<&ConnectionManagerHandle>,
    ws: WebSocket,
) -> Result<impl IntoResponse> {
    let user_id: Uuid = session.get(AUTH_COOKIE_ID_FIELD).context("Invalid login")?;

    let cm_handle = cm.clone();

    if let Some(user) = user::Entity::find_by_id(user_id).one(*db).await? {
        let device_ids: Vec<Uuid> = user
            .find_related(device::Entity)
            .all(*db)
            .await?
            .into_iter()
            .map(|d| d.id)
            .collect();

        return Ok(ws.on_upgrade(move |socket| async move {
            let _ = cm_handle
                .new_client(IncomingUserConnection {
                    id: user.id.clone(),
                    username: user.username.clone(),
                    devices: device_ids,
                    socket,
                })
                .await;
        }));
    }

    bail!("Unauthenticated")
}

pub(crate) fn ws_routes(db: DatabaseConnection) -> impl Endpoint {
    Route::new().at("/device", get(connect_device)).nest(
        "/client",
        Route::new().at("/", get(connect_client).with(RequireAuth { db })),
    )
}
