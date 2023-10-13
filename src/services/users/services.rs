use super::models::{CreateUser, LoginClaims, LoginUser, UpdateUser, UserWithoutPassword};
use crate::AppState;
use actix_web::{get, post, put, web, HttpResponse, Responder};
use chrono::{TimeZone, Utc};

#[get("/users")]
async fn get_all_users(data: web::Data<AppState>) -> impl Responder {
    let result = sqlx::query!("SELECT * FROM users")
        .fetch_all(&data.postgres_client)
        .await;

    match result {
        Ok(users) => HttpResponse::Ok().json(
            users
                .iter()
                .map(|user| UserWithoutPassword {
                    id: user.id,
                    username: user.username.clone(),
                    email: user.email.clone(),
                    created_at: Utc.from_utc_datetime(&user.created_at),
                    updated_at: Utc.from_utc_datetime(&user.updated_at),
                })
                .collect::<Vec<UserWithoutPassword>>(),
        ),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[get("/users/{id}")]
async fn get_user_by_id(data: web::Data<AppState>, id: web::Path<i32>) -> impl Responder {
    let result = sqlx::query!("SELECT * FROM users WHERE id = $1", id.into_inner())
        .fetch_one(&data.postgres_client)
        .await;

    match result {
        Ok(user) => HttpResponse::Ok().json(UserWithoutPassword {
            id: user.id,
            username: user.username,
            email: user.email,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        }),
        Err(_) => HttpResponse::NotFound().finish(),
    }
}

#[post("/users")]
async fn create_user(data: web::Data<AppState>, body: web::Json<CreateUser>) -> impl Responder {
    if body.email.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Email is required"}));
    }
    if body.username.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Username is required"}));
    }
    if body.password.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Password is required"}));
    }

    let hashed = bcrypt::hash(body.password.clone(), 10).expect("Failed to hash password");

    let result = sqlx::query!(
        "INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING *",
        body.username,
        body.email,
        &hashed
    )
    .fetch_one(&data.postgres_client)
    .await;

    match result {
        Ok(user) => HttpResponse::Ok().json(UserWithoutPassword {
            id: user.id,
            username: user.username,
            email: user.email,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        }),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[put("/users/{id}")]
async fn update_user(
    data: web::Data<AppState>,
    id: web::Path<i32>,
    body: web::Json<UpdateUser>,
) -> impl Responder {
    if body.email.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Email is required"}));
    }
    if body.username.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Username is required"}));
    }
    if body.password.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Password is required"}));
    }

    let result = sqlx::query!(
        "UPDATE users SET username = $1, email = $2 WHERE id = $3 RETURNING *",
        body.username,
        body.email,
        id.into_inner()
    )
    .fetch_one(&data.postgres_client)
    .await;

    match result {
        Ok(user) => HttpResponse::Ok().json(UserWithoutPassword {
            id: user.id,
            username: user.username,
            email: user.email,
            created_at: Utc.from_utc_datetime(&user.created_at),
            updated_at: Utc.from_utc_datetime(&user.updated_at),
        }),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[post("/users/login")]
async fn login_user(data: web::Data<AppState>, body: web::Json<LoginUser>) -> impl Responder {
    if body.email.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Email is required"}));
    }
    if body.password.is_empty() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Password is required"}));
    }

    let result = sqlx::query!("SELECT * FROM users WHERE email = $1", body.email)
        .fetch_one(&data.postgres_client)
        .await;

    match result {
        Ok(user) => {
            let is_valid = bcrypt::verify(body.password.clone(), &user.password)
                .expect("Failed to verify password");

            if is_valid {
                let claims = LoginClaims {
                    sub: user.id.to_string(),
                    email: user.email,
                    exp: (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize,
                };
                let token = jsonwebtoken::encode(
                    &jsonwebtoken::Header::default(),
                    &claims,
                    &jsonwebtoken::EncodingKey::from_secret(data.json_web_token_secret.as_bytes()),
                )
                .unwrap();

                HttpResponse::Ok().json(serde_json::json!({ "token": token }))
            } else {
                HttpResponse::NotFound().json(serde_json::json!({"error": "Credentials not found"}))
            }
        }
        Err(_) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Credentials not found"}))
        }
    }
}

pub fn users_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(get_all_users)
        .service(create_user)
        .service(get_user_by_id)
        .service(update_user)
        .service(login_user);
}
