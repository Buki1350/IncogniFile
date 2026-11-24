use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use std::{str::FromStr, time::Duration};

pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));
    // 1 application instance and 1 connection for demo
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(options)
        .await?;
    let legacy = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM pragma_table_info('users') WHERE name='username'",
    )
    .fetch_one(&pool)
    .await?;
    if legacy > 0 {
        return Err(sqlx::Error::Protocol("Old username database: keep a backup and use a fresh SQLite database for email accounts (DATABASE_URL=sqlite:incognifile-email.db).".into()));
    }
    sqlx::raw_sql(include_str!("../database/schema.sql"))
        .execute(&pool)
        .await?;
    Ok(pool)
}
