use sqlx::postgres::{PgPool, PgPoolOptions};
use std::env;

pub async fn start_connection() -> PgPool {
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(database_url.as_str())
        .await
        .expect("Failed to connect to Postgres");

    sqlx::migrate!("src/databases/postgres/migrations")
        .run(&pool)
        .await
        .expect("Failed to run migrations");

    pool
}
