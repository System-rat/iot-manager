use std::str::FromStr;

use anyhow::{Context, Result};
use argon2::{
    password_hash::rand_core::{OsRng, RngCore},
    Argon2,
};
use askama::Template;
use base64::Engine;
use poem::{
    handler,
    http::{header::LOCATION, StatusCode},
    post,
    session::Session,
    web::{Data, Form, Html},
    Endpoint, EndpointExt, IntoResponse, Response, Route, RouteMethod,
};
use sea_orm::{prelude::*, DatabaseConnection, IntoActiveModel, ModelTrait, Set};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{RequireAuth, AUTH_COOKIE_ID_FIELD},
    entities::user::Entity as User,
};

use crate::entities::device;
use crate::entities::prelude::*;

#[derive(Template)]
#[template(path = "device/index.html.askama", escape = "html")]
struct IndexPage {
    devices: Vec<DeviceDTO>,
}

#[derive(Serialize)]
struct DeviceDTO {
    name: String,
    id: String,
}

impl From<device::Model> for DeviceDTO {
    fn from(value: device::Model) -> Self {
        DeviceDTO {
            name: value.device_name,
            id: value.id.to_string(),
        }
    }
}

#[handler]
async fn index(session: &Session, db: Data<&DatabaseConnection>) -> Result<Html<String>> {
    let user = User::find_by_id(
        session
            .get::<Uuid>("id")
            .context("User must be logged in")?,
    )
    .one(*db)
    .await?
    .context("User doesn't exits in the DB. Invalid login")?;

    let devices: Vec<DeviceDTO> = user
        .find_related(Device)
        .all(*db)
        .await?
        .into_iter()
        .map(|device| device.into())
        .collect();

    Ok(Html(IndexPage { devices }.render()?))
}

#[derive(Template)]
#[template(path = "device/create_device_form.html.askama", escape = "html")]
struct CreateDevicePage;

#[derive(Deserialize)]
struct CreateDeviceForm {
    name: String,
}

#[derive(Deserialize)]
struct ResetDevicePasswordForm {
    id: String,
}

#[derive(Deserialize)]
struct DeleteDeviceForm {
    id: String,
}

#[derive(Template)]
#[template(path = "device/create_device_result.html.askama", escape = "html")]
struct DeviceCreatedResponsePage {
    device_id: String,
    device_code: String,
}

#[handler]
async fn create_device_form() -> Result<Html<String>> {
    Ok(Html(CreateDevicePage.render()?))
}

pub(crate) const DEVICE_KEY_STRING_LENGTH: usize = 10;
pub(crate) const DEVICE_KEY_HASH_LENGTH: usize = 50;
pub(crate) const DEVICE_KEY_SALT_LENGTH: usize = 50;

#[handler]
async fn create_device(
    session: &Session,
    db: Data<&DatabaseConnection>,
    Form(form_data): Form<CreateDeviceForm>,
) -> Result<Html<String>> {
    let (hash, salt, readable_string) = generate_device_key()?;

    let model = device::Model {
        id: uuid::Uuid::new_v4(),
        device_name: form_data.name,
        owner: session
            .get(AUTH_COOKIE_ID_FIELD)
            .context("Invalid user login")?,
        device_key_hash: hash.to_vec(),
        device_key_salt: salt.to_vec(),
    };

    let res = Device::insert(model.into_active_model()).exec(*db).await?;

    Ok(Html(
        DeviceCreatedResponsePage {
            device_id: res.last_insert_id.to_string(),
            device_code: readable_string,
        }
        .render()?,
    ))
}

#[handler]
pub(crate) async fn reset_device_code(
    db: Data<&DatabaseConnection>,
    Form(form): Form<ResetDevicePasswordForm>,
) -> Result<Html<String>> {
    let device_id = Uuid::from_str(&form.id)?;
    let (hash, salt, key) = generate_device_key()?;

    device::Entity::update(device::ActiveModel {
        id: Set(device_id),
        device_key_hash: Set(hash.to_vec()),
        device_key_salt: Set(salt.to_vec()),
        ..Default::default()
    })
    .exec(*db)
    .await?;

    Ok(Html(
        DeviceCreatedResponsePage {
            device_id: device_id.to_string(),
            device_code: key,
        }
        .render()?,
    ))
}

#[handler]
pub(crate) async fn delete_device(
    db: Data<&DatabaseConnection>,
    Form(form): Form<DeleteDeviceForm>,
) -> Result<impl IntoResponse> {
    let device_id = Uuid::from_str(&form.id)?;
    device::Entity::delete(device::ActiveModel {
        id: Set(device_id),
        ..Default::default()
    })
    .exec(*db)
    .await?;

    Ok(Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, "/devices")
        .finish())
}

pub(crate) fn device_routes(db: DatabaseConnection) -> impl Endpoint {
    Route::new()
        .at("/", RouteMethod::new().get(index))
        .at(
            "/create",
            RouteMethod::new()
                .get(create_device_form)
                .post(create_device),
        )
        .at("/reset-key", post(reset_device_code))
        .at("/delete", post(delete_device))
        .with(RequireAuth { db })
}

fn generate_device_key() -> Result<(
    [u8; DEVICE_KEY_HASH_LENGTH],
    [u8; DEVICE_KEY_SALT_LENGTH],
    String,
)> {
    let mut key = [0u8; DEVICE_KEY_STRING_LENGTH];
    let mut salt = [0u8; DEVICE_KEY_SALT_LENGTH];
    let mut device_key = [0u8; DEVICE_KEY_HASH_LENGTH];

    OsRng.fill_bytes(&mut key);
    OsRng.fill_bytes(&mut salt);

    let key_string = base64::prelude::BASE64_STANDARD.encode(key);

    Argon2::default().hash_password_into(key_string.as_bytes(), &salt, &mut device_key)?;

    Ok((device_key, salt, key_string))
}
