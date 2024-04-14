use anyhow::Result;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use migration::{Migrator, MigratorTrait};
use sea_orm::{ActiveValue, ConnectOptions, Database, DatabaseConnection, EntityTrait};
use tracing::info;
use tracing_subscriber::prelude::*;

mod entities;
use entities::prelude::*;

const DEFAULT_USER_USERNAME: &str = "admin";
const DEFAULT_USER_PASSWORD: &str = "red1337";

const PASSWORD_HASH_LEN: usize = 50;
const PASSWORD_SALT_LEN: usize = 50;

fn setup_tracing() -> Result<()> {
    tracing::subscriber::set_global_default(
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::filter::EnvFilter::builder()
                    .with_default_directive(tracing_subscriber::filter::LevelFilter::ERROR.into())
                    .from_env_lossy()
                    .add_directive("iot_manager=INFO".parse()?),
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

    Ok(())
}
