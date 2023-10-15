use actix_web::{
    dev::Service, get, http::header::HeaderName, web, App, HttpResponse, HttpServer, Responder,
};
#[cfg(debug_assertions)]
use dotenv::dotenv;
use serde_json::json;
use services::users::services::users_routes;
use sqlx::PgPool;
use std::env;
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
    #[cfg(debug_assertions)]
    dotenv().ok();
    env::set_var("RUST_BACKTRACE", "1");

    let json_web_token_environment =
        std::env::var("JSON_WEB_TOKEN_SECRET").expect("JSON_WEB_TOKEN_SECRET must be set");

    let port: String = env::var("PORT").expect("PORT must be set");

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
            .wrap_fn(|req, srv| {
                let proxy_authorization_header =
                    HeaderName::from_lowercase(b"proxy-authorization").unwrap();
                let proxy_authorization = req.headers().get(&proxy_authorization_header).cloned();
                let proxy_authorization_environment = std::env::var("PROXY_AUTHORIZATION").unwrap();
                let res = srv.call(req);
                async move {
                    let res = res.await?;
                    match proxy_authorization {
                        Some(authorization) => {
                            let auth = authorization;
                            if proxy_authorization_environment != auth.to_str().unwrap() {
                                return Err(actix_web::error::ErrorUnauthorized(json!({
                                    "message": "Unauthorized request"
                                }))
                                .into());
                            }
                        }
                        None => {
                            return Err(actix_web::error::ErrorUnauthorized(json!({
                                "message": "Unauthorized request"
                            }))
                            .into());
                        }
                    }
                    Ok(res)
                }
            })
            .wrap(cors)
    })
    .bind((
        "0.0.0.0",
        port.parse::<u16>().expect("PORT must be a number"),
    ))?
    .run()
    .await
}
