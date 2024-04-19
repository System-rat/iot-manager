use anyhow::{Context, Result};
use argon2::password_hash::rand_core::{OsRng, RngCore};
use askama::Template;
use migration::{Migrator, MigratorTrait};
use poem::{
    get, handler,
    http::{header, StatusCode},
    listener::TcpListener,
    middleware::{AddData, Csrf},
    session::{CookieConfig, CookieSession, Session},
    web::{cookie::CookieKey, CsrfToken, CsrfVerifier, Data, Form, Html},
    Endpoint, EndpointExt, Middleware, Response, Route, RouteMethod, Server,
};
use sea_orm::{
    ActiveValue, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    QueryFilter,
};
use serde::Deserialize;
use tracing::info;
use tracing_subscriber::prelude::*;

mod entities;
use entities::prelude::*;

const DEFAULT_USER_USERNAME: &str = "admin";
const DEFAULT_USER_PASSWORD: &str = "red1337";

const PASSWORD_HASH_LEN: usize = 50;
const PASSWORD_SALT_LEN: usize = 50;

#[derive(Template)]
#[template(path = "main.html.askama", escape = "html")]
struct MainPage {
    user_count: usize,
}

#[derive(Template)]
#[template(
    source = "{% extends \"base.html.askama\" %}
           {% block title %} IoT Manager {% endblock %}
           {% block body %}Hello, World!{% endblock %}",
    ext = "html"
)]
struct IndexPage;

#[derive(Template)]
#[template(path = "error/404.html.askama", escape = "html")]
struct NotFoundErrorPage;

#[derive(Template)]
#[template(path = "error/unauthorized.html.askama", escape = "html")]
struct UnauthorizedErrorPage;

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

fn setup_tracing() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::filter::EnvFilter::builder()
                    .with_default_directive(tracing_subscriber::filter::LevelFilter::ERROR.into())
                    .from_env_lossy()
                    .add_directive("iot_manager=DEBUG".parse()?),
            )
            .with(tracing_subscriber::fmt::layer().with_ansi(true))
            .with(tracing_journald::layer()?),
    )?;

    Ok(())
}

#[tracing::instrument(level = "trace")]
async fn ensure_admin_account(db: &DatabaseConnection) -> Result<()> {
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

        argon2::Argon2::default().hash_password_into(
            DEFAULT_USER_PASSWORD.as_bytes(),
            &password_salt_bytes,
            &mut password_hash,
        )?;

        let admin_user = entities::user::ActiveModel {
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

struct RequireAuth {
    db: DatabaseConnection,
}

struct RequireAuthImpl<E> {
    ep: E,
    db: DatabaseConnection,
}

const AUTH_COOKIE_SECRET_FIELD: &str = "beans";
const AUTH_COOKIE_USERNAME_FIELD: &str = "username";
const AUTH_COOKIE_SECRET: &str = "that's beans";

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
            .filter(entities::user::Column::Username.eq(username))
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

#[handler]
async fn test_page(db: Data<&DatabaseConnection>) -> Html<String> {
    let count = User::find()
        .all(*db)
        .await
        .map(|u| u.len())
        .unwrap_or_default();

    Html(
        MainPage { user_count: count }
            .render()
            .unwrap_or("".to_string()),
    )
}

fn make_unauthorized_error() -> poem::Error {
    poem::Error::from_response(
        Response::builder().status(StatusCode::UNAUTHORIZED).body(
            UnauthorizedErrorPage
                .render()
                .unwrap_or_else(|_| "Unauthorized".to_string()),
        ),
    )
}

fn make_internal_error() -> poem::Error {
    poem::Error::from_response(
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body("Error 500. Internal Server Error"),
    )
}

#[handler]
async fn login_submit(
    session: &Session,
    db: Data<&DatabaseConnection>,
    verifier: &CsrfVerifier,
    Form(login_form): Form<LoginForm>,
) -> poem::Result<Response> {
    if !verifier.is_valid(&login_form.csrf_token) {
        return Err(make_unauthorized_error());
    }

    let user = User::find()
        .filter(entities::user::Column::Username.eq(login_form.username))
        .one(*db)
        .await
        .context(make_internal_error())?;

    if let Some(user) = user {
        let mut hashed_password = [0u8; 50];

        argon2::Argon2::default()
            .hash_password_into(
                login_form.password.as_bytes(),
                &user.password_salt,
                &mut hashed_password,
            )
            .context(make_internal_error())?;

        if hashed_password != *user.password_hash {
            return Err(make_unauthorized_error());
        }

        session.set(AUTH_COOKIE_SECRET_FIELD, AUTH_COOKIE_SECRET.as_bytes());
        session.set(AUTH_COOKIE_USERNAME_FIELD, user.username);

        Ok(Response::builder()
            .status(StatusCode::FOUND)
            .header(header::LOCATION, "/")
            .finish())
    } else {
        Err(make_unauthorized_error())
    }
}

#[handler]
async fn login(token: &CsrfToken) -> poem::Result<Html<String>> {
    Ok(Html(
        LoginPage {
            csrf_token: token.0.to_string(),
        }
        .render()
        .context(make_internal_error())?,
    ))
}

#[handler]
async fn index_page() -> Html<String> {
    Html(
        IndexPage
            .render()
            .unwrap_or_else(|_| "Home page".to_string()),
    )
}

async fn run_poem(db: DatabaseConnection) -> Result<()> {
    let app = Route::new()
        .at("/", get(index_page))
        .nest_no_strip(
            "/test",
            Route::new()
                .at("/test", get(test_page))
                .with(RequireAuth { db: db.clone() }),
        )
        .at("/login", RouteMethod::new().get(login).post(login_submit))
        .with(CookieSession::new(CookieConfig::private(
            CookieKey::generate(),
        )))
        .with(AddData::new(db))
        .with(Csrf::new())
        .catch_error(|_: poem::error::NotFoundError| async move {
            Response::builder().status(StatusCode::NOT_FOUND).body(
                NotFoundErrorPage
                    .render()
                    .unwrap_or_else(|_| "Not found".to_string()),
            )
        });

    Server::new(TcpListener::bind("0.0.0.0:1337"))
        .name("iot-manager")
        .run(app)
        .await
        .context("Server error")
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_tracing()?;

    let options = ConnectOptions::new("postgres://localhost/iot-manager");
    let db = Database::connect(options).await?;

    info!("Pinging database: {}", db.ping().await.is_ok());

    info!("Running migration...");

    Migrator::up(&db, None).await?;

    info!("Migration done");

    info!("Ensuring admin account..");

    ensure_admin_account(&db).await?;

    info!("Starting server");

    run_poem(db.clone()).await?;

    Ok(())
}
