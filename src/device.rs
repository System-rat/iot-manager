use anyhow::{Context, Result};
use argon2::{
    password_hash::rand_core::{OsRng, RngCore},
    Argon2,
};
use askama::Template;
use base64::Engine;
use poem::{
    handler,
    session::Session,
    web::{Data, Form, Html},
    Endpoint, EndpointExt, Route, RouteMethod,
};
use sea_orm::{prelude::*, DatabaseConnection, IntoActiveModel, ModelTrait};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{RequireAuth, AUTH_COOKIE_ID_FIELD},
    entities::user::Entity as User,
};

use crate::entities::prelude::*;
use crate::entities::device;

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

const DEVICE_KEY_STRING_LENGTH: usize = 10;
const DEVICE_KEY_HASH_LENGTH: usize = 50;
const DEVICE_KEY_SALT_LENGTH: usize = 50;

#[handler]
async fn create_device(
    session: &Session,
    db: Data<&DatabaseConnection>,
    Form(form_data): Form<CreateDeviceForm>,
) -> Result<Html<String>> {
    let mut key = [0u8; DEVICE_KEY_STRING_LENGTH];
    OsRng.fill_bytes(&mut key);

    let readable_string = base64::prelude::BASE64_STANDARD.encode(key);

    let mut hash = [0u8; DEVICE_KEY_HASH_LENGTH];
    let mut salt = [0u8; DEVICE_KEY_SALT_LENGTH];
    OsRng.fill_bytes(&mut salt);

    Argon2::default().hash_password_into(readable_string.as_bytes(), &salt, &mut hash)?;

    let model = device::Model {
        id: uuid::Uuid::new_v4(),
        device_name: form_data.name,
        owner: session
            .get(AUTH_COOKIE_ID_FIELD)
            .context("Invalid user login")?,
        device_key_hash: hash.to_vec(),
        device_key_salt: salt.to_vec(),
    };

    let res = Device::insert(model.into_active_model())
        .exec(*db)
        .await?;

    Ok(Html(
        DeviceCreatedResponsePage {
            device_id: res.last_insert_id.to_string(),
            device_code: readable_string,
        }
        .render()?,
    ))
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
        .with(RequireAuth { db })
}
