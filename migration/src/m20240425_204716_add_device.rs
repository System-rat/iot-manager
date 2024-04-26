use sea_orm_migration::prelude::*;

use crate::m20220101_000001_create_table::User;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(Device::Table)
                    .if_not_exists()
                    .col(ColumnDef::new(Device::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Device::DeviceName).string_len(20).not_null())
                    .col(ColumnDef::new(Device::Owner).uuid().not_null())
                    .col(
                        ColumnDef::new(Device::DeviceKeyHash)
                            .binary_len(50)
                            .not_null(),
                    )
                    .col(
                        ColumnDef::new(Device::DeviceKeySalt)
                            .binary_len(50)
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Device::Table, Device::Owner)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(Device::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum Device {
    Table,
    Id,
    DeviceName,
    Owner,
    DeviceKeyHash,
    DeviceKeySalt,
}
