use anyhow::{Context, Result};
use askama::Template;
use device::device_routes;
use poem::{
    get, handler,
    listener::TcpListener,
    middleware::{AddData, Csrf},
    session::{CookieConfig, CookieSession},
    web::{cookie::CookieKey, Data, Html},
    EndpointExt, Route, Server,
};
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait};
use tracing::{debug, info};
use tracing_subscriber::prelude::*;

mod auth;
mod device;
mod entities;
mod error;

use crate::auth::ensure_admin_account;
use auth::{auth_routes, RequireAuth};
use entities::prelude::*;
use error::make_not_found_response;
use migration::{Migrator, MigratorTrait};

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
        .nest_no_strip("/login", auth_routes())
        .nest("/devices", device_routes(db.clone()))
        .with(CookieSession::new(CookieConfig::private(
            CookieKey::generate(),
        )))
        .with(AddData::new(db))
        .with(Csrf::new())
        .catch_error(|_: poem::error::NotFoundError| async move { make_not_found_response() });

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

    debug!("Pinging database: {}", db.ping().await.is_ok());

    info!("Running migration...");

    Migrator::up(&db, None).await?;

    info!("Migration done");

    info!("Ensuring admin account..");

    ensure_admin_account(&db).await?;

    info!("Starting server");

    run_poem(db.clone()).await?;

    Ok(())
}
