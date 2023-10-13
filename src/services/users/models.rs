use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub password: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct UserWithoutPassword {
    pub id: i32,
    pub username: String,
    pub email: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize)]
pub struct CreateUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct UpdateUser {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct LoginClaims {
    pub sub: String,
    pub email: String,
    pub exp: usize,
}
