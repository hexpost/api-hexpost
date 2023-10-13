use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use dotenv::dotenv;
use services::users::services::users_routes;
use sqlx::PgPool;

mod databases {
    pub mod postgres;
}
mod services {
    pub mod users;
}

#[derive(Clone)]
pub struct AppState {
    postgres_client: PgPool,
    json_web_token_secret: String,
}

#[get("/health")]
async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok"
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let json_web_token_environment =
        std::env::var("JSON_WEB_TOKEN_SECRET").expect("JSON_WEB_TOKEN_SECRET must be set");

    let pool = databases::postgres::start_connection().await;

    HttpServer::new(move || {
        let cors = actix_cors::Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .app_data(web::Data::new(AppState {
                postgres_client: pool.clone(),
                json_web_token_secret: json_web_token_environment.clone(),
            }))
            .service(health)
            .configure(users_routes)
            .wrap(cors)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
