use anyhow::Context;
use argon2::{
    password_hash::rand_core::{OsRng, RngCore},
    Argon2,
};
use askama::Template;
use poem::{
    handler,
    http::{header, StatusCode},
    session::Session,
    web::{CsrfToken, CsrfVerifier, Data, Form, Html},
    Endpoint, Middleware, Response, Route, RouteMethod,
};
use sea_orm::{ActiveValue, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Deserialize;
use tracing::info;

use crate::{
    entities::user,
    error::{make_internal_error, make_unauthorized_error},
    User,
};

// --------------------
// Constants
// --------------------

const AUTH_COOKIE_SECRET_FIELD: &str = "beans";
pub(crate) const AUTH_COOKIE_USERNAME_FIELD: &str = "username";
pub(crate) const AUTH_COOKIE_ID_FIELD: &str = "id";
const AUTH_COOKIE_SECRET: &str = "that's beans";

const DEFAULT_USER_USERNAME: &str = "admin";
const DEFAULT_USER_PASSWORD: &str = "red1337";

const PASSWORD_HASH_LEN: usize = 50;
const PASSWORD_SALT_LEN: usize = 50;

// -------------------------
// Authentication middleware
// -------------------------

pub(crate) struct RequireAuth {
    pub(crate) db: DatabaseConnection,
}

pub(crate) struct RequireAuthImpl<E> {
    ep: E,
    db: DatabaseConnection,
}

impl<E: Endpoint> Middleware<E> for RequireAuth {
    type Output = RequireAuthImpl<E>;

    fn transform(&self, ep: E) -> Self::Output {
        RequireAuthImpl {
            ep,
            db: self.db.clone(),
        }
    }
}

impl<E: Endpoint> Endpoint for RequireAuthImpl<E> {
    type Output = E::Output;

    async fn call(&self, req: poem::Request) -> poem::Result<Self::Output> {
        let session = req.extensions().get::<Session>().context("No session")?;

        let username = session
            .get::<String>(AUTH_COOKIE_USERNAME_FIELD)
            .ok_or_else(make_unauthorized_error)?;

        let user = User::find()
            .filter(user::Column::Username.eq(username))
            .one(&self.db)
            .await
            .context(make_internal_error())?;

        if user.is_some()
            && session
                .get::<Vec<u8>>(AUTH_COOKIE_SECRET_FIELD)
                .context(make_unauthorized_error())?
                == AUTH_COOKIE_SECRET.as_bytes()
        {
            return self.ep.call(req).await;
        }

        Err(make_unauthorized_error())
    }
}

// --------------------
// Pages and routes
// --------------------

#[derive(Template)]
#[template(path = "login.html.askama", escape = "html")]
struct LoginPage {
    csrf_token: String,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
    csrf_token: String,
}

#[tracing::instrument(level = "trace")]
pub(crate) async fn ensure_admin_account(db: &DatabaseConnection) -> anyhow::Result<()> {
    let users = User::find().all(db).await?;

    if users.len() == 0
        || users
            .iter()
            .find(|u| u.username.to_lowercase() == "admin")
            .is_none()
    {
        info!("No admin account present, generating new one...");
        let mut password_hash = [0u8; PASSWORD_HASH_LEN];
        let mut password_salt_bytes = [0u8; PASSWORD_SALT_LEN];

        OsRng.fill_bytes(&mut password_salt_bytes);

        Argon2::default().hash_password_into(
            DEFAULT_USER_PASSWORD.as_bytes(),
            &password_salt_bytes,
            &mut password_hash,
        )?;

        let admin_user = user::ActiveModel {
            id: ActiveValue::Set(uuid::Uuid::new_v4()),
            username: ActiveValue::Set(DEFAULT_USER_USERNAME.to_string()),
            password_hash: ActiveValue::Set(password_hash.to_vec()),
            password_salt: ActiveValue::Set(password_salt_bytes.to_vec()),
            ..Default::default()
        };

        User::insert(admin_user).exec(db).await?;
    }
    Ok(())
}

#[handler]
pub(crate) async fn login_submit(
    session: &Session,
    db: Data<&DatabaseConnection>,
    verifier: &CsrfVerifier,
    Form(login_form): Form<LoginForm>,
) -> poem::Result<Response> {
    if !verifier.is_valid(&login_form.csrf_token) {
        return Err(make_unauthorized_error());
    }

    let user = User::find()
        .filter(user::Column::Username.eq(&login_form.username))
        .one(*db)
        .await
        .context(make_internal_error())?;

    if let Some(user) = user {
        let mut hashed_password = [0u8; 50];

        Argon2::default()
            .hash_password_into(
                login_form.password.as_bytes(),
                &user.password_salt,
                &mut hashed_password,
            )
            .context(make_internal_error())?;

        if hashed_password != *user.password_hash {
            info!("Invalid password for {}", user.username);
            return Err(make_unauthorized_error());
        }

        session.set(AUTH_COOKIE_SECRET_FIELD, AUTH_COOKIE_SECRET.as_bytes());
        session.set(AUTH_COOKIE_USERNAME_FIELD, &user.username);
        session.set(AUTH_COOKIE_ID_FIELD, &user.id);

        info!("New login for {} successful", user.username);

        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/")
            .finish())
    } else {
        info!(
            "Non existing user login attempt for username \"{}\"",
            login_form.username
        );
        Err(make_unauthorized_error())
    }
}

#[handler]
pub(crate) async fn login(token: &CsrfToken) -> poem::Result<Html<String>> {
    Ok(Html(
        LoginPage {
            csrf_token: token.0.to_string(),
        }
        .render()
        .context(make_internal_error())?,
    ))
}

pub(crate) fn auth_routes() -> Route {
    Route::new().at("/login", RouteMethod::new().get(login).post(login_submit))
}
