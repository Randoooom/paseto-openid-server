/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2022 Randoooom
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in the
 * Software without restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
 * IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */

use crate::database::client::{
    hash_password, Client, ClientAuthenticationData, ClientVerificationToken, Gender,
};
use crate::error::ResponseError;
use crate::locator::mail::MailOptions;
use crate::locator::LocatorPointer;
use crate::middleware::SessionId;
use crate::openid::verification::Verification;
use crate::ROOT;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use rbatis::crud::CRUD;

#[derive(Deserialize, Serialize, TypedBuilder)]
pub struct AuthenticationRequest {
    /// the username / nickname of the client
    nickname: String,
    /// the password
    password: String,
    /// the totp
    token: Option<String>,
}

pub async fn post_login(
    Json(data): Json<AuthenticationRequest>,
    Extension(locator): Extension<LocatorPointer>,
) -> impl IntoResponse {
    // lock the locator
    let mut locked = locator.lock().await;
    // get the connection
    let connection = locked.connection();

    // get the client
    let client = Client::from_nickname(data.nickname.as_str(), &connection)
        .await
        .unwrap();
    if let Some(client) = client {
        // get the auth data
        let authentication_data = client.authentication_data(&connection).await.unwrap();

        if let Some(authentication_data) = authentication_data {
            // authenticate
            if authentication_data.login(data.password.as_str(), data.token.as_deref()) {
                // start the session
                let session = locked.auth_mut().start_session(client.sub().clone());
                // return the session
                return Ok((StatusCode::OK, Json(json!({ "session_id": session }))));
            }
        }
    }

    // return 401
    Err(ResponseError::Unauthorized)
}

#[derive(Deserialize, Serialize)]
pub struct SignupRequest {
    /// The full name in displayable form
    name: String,
    /// The first name(s) of the user
    given_name: String,
    /// The last name
    family_name: String,
    /// The middle name(s) of the user
    middle_name: Option<String>,
    /// The nickname of the user (unique)
    nickname: String,
    /// The preffered name of the user (must not be unique)
    preferred_username: String,
    /// The url to the data of the user
    profile: String,
    /// The url to a picture of the user?
    picture: String,
    /// The website or blog of the user
    website: Option<String>,
    /// The email of the user
    email: String,
    /// the gender
    gender: Gender,
    /// The birthdate as iso
    birthdate: String,
    /// the timezone
    zoneinfo: String,
    /// the users locale
    locale: String,
    /// The phone number of the user
    phone_number: Option<String>,
    /// the password,
    password: String,
}

pub async fn post_signup(
    Json(data): Json<SignupRequest>,
    Extension(locator): Extension<LocatorPointer>,
) -> impl IntoResponse {
    // lock the locator
    let locked = locator.lock().await;

    // verify the strength of the password
    if !Verification::password_strong_enough(data.password.as_str()) {
        return Err(ResponseError::BadRequest(
            "Password not strong enough".into(),
        ));
    }
    // validate the email (check via regex)
    if !Verification::email_valid(data.email.as_str()) {
        return Err(ResponseError::BadRequest("Email not valid".into()));
    }

    // build the client
    let client = Client::builder()
        .nickname(&data.nickname)
        .birthdate(&data.birthdate)
        .email(&data.email)
        .family_name(&data.family_name)
        .gender(data.gender.clone())
        .given_name(&data.given_name)
        .locale(&data.locale)
        .middle_name(data.middle_name.clone())
        .name(&data.name)
        .phone_number(data.phone_number.clone())
        .picture(&data.picture)
        .preferred_username(&data.preferred_username)
        .profile(&data.profile)
        .website(data.website.clone())
        .zoneinfo(&data.zoneinfo)
        .build();

    // build the authentication data
    let auth_data = ClientAuthenticationData::builder()
        .client(client.sub().clone())
        .password(data.password.clone())
        .build();

    // get the connection
    let connection = locked.connection();
    // save the data
    connection.save(&client, &[]).await.unwrap();
    connection.save(&auth_data, &[]).await.unwrap();

    // send the email verification
    let _ = {
        // setup the verification token
        let token = ClientVerificationToken::builder()
            .client(client.sub().clone())
            .build();
        // save it
        connection.save(&token, &[]).await.unwrap();

        // setup the mail
        let mail = MailOptions::builder()
            .subject("E-Mail Verification".to_string())
            .to(client.email().clone())
            .content(
                format!(
                    "Hey {name}!</br>Please click <a href={root}/verify_email?token={token}>here</a> to verify your E-Mail!",
                    name = client.preferred_username(),
                    root = ROOT.as_str(),
                    token = token.uuid()
                )
            )
            .build();
        // send it
        locked.mail().send(mail).await.unwrap();
    };

    Ok((StatusCode::CREATED, Json(json!(client))))
}

pub async fn post_logout(
    Extension(locator): Extension<LocatorPointer>,
    Extension(session_id): Extension<SessionId>,
) -> impl IntoResponse {
    // lock the locator
    let mut locked = locator.lock().await;

    // end the session
    locked.auth_mut().end_session(session_id.0.as_str());

    StatusCode::OK
}

#[derive(Deserialize, Serialize)]
pub struct UpdatePassword {
    password: String,
}

pub async fn put_password(
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
    Json(update): Json<UpdatePassword>,
    Extension(session_id): Extension<SessionId>,
) -> impl IntoResponse {
    // verify the strength of the password
    if !Verification::password_strong_enough(update.password.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "password not strong enough"})),
        );
    }

    // lock
    let mut locator = locator.lock().await;
    let connection = locator.connection();
    // get the auth data of the client
    let mut auth = client
        .authentication_data(connection)
        .await
        .unwrap()
        .unwrap();

    // hash the new password
    let hashed = hash_password(update.password);
    // update
    auth.set_password(hashed);
    connection.update_by_column("uuid", &auth).await.unwrap();

    // end the session
    locator.auth_mut().end_session(session_id.0.as_str());

    (
        StatusCode::OK,
        Json(json!({"message": "Changed password. Session canceled."})),
    )
}

#[derive(Deserialize, Serialize)]
pub struct ActivateTOTP {
    token: String,
}

pub async fn post_activate_totp(
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
    Json(activate): Json<ActivateTOTP>,
) -> impl IntoResponse {
    // lock the locator
    let locator = locator.lock().await;
    let connection = locator.connection();

    // get the auth data
    let mut auth = client
        .authentication_data(connection)
        .await
        .unwrap()
        .unwrap();
    // verify the token
    if !auth.validate_totp(activate.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid token"})),
        );
    }

    // update
    auth.set_totp(true);
    connection.update_by_column("uuid", &auth).await.unwrap();

    (StatusCode::OK, Json(json!({"message": "Enabled"})))
}

pub async fn post_disable_totp(
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
    Json(verification): Json<ActivateTOTP>,
) -> impl IntoResponse {
    // lock the locator
    let locator = locator.lock().await;
    let connection = locator.connection();
    // get the auth data
    let mut authentication_data = client
        .authentication_data(&connection)
        .await
        .unwrap()
        .unwrap();

    // verify the token
    if !authentication_data.validate_totp(verification.token.as_str()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "Invalid token"})),
        );
    }

    // regenerate the secret
    authentication_data.set_secret(ClientAuthenticationData::gen_secret());
    authentication_data.set_totp(false);
    // update
    connection
        .update_by_column("uuid", &authentication_data)
        .await
        .unwrap();

    (StatusCode::OK, Json(json!({"message": "Disabled"})))
}

pub async fn get_qr_code(
    Extension(client): Extension<Client>,
    Extension(locator): Extension<LocatorPointer>,
) -> impl IntoResponse {
    // lock
    let locator = locator.lock().await;
    let connection = locator.connection();

    // get the auth data
    let authentication_data = client
        .authentication_data(connection)
        .await
        .unwrap()
        .unwrap();

    authentication_data.get_qr_code(client.nickname().as_str())
}

#[cfg(test)]
impl Default for SignupRequest {
    fn default() -> Self {
        Self {
            name: "Nick Name".to_string(),
            given_name: "Nick".to_string(),
            family_name: "Name".to_string(),
            middle_name: None,
            nickname: "Nickname".to_string(),
            preferred_username: "Crazy Name".to_string(),
            // TODO
            profile: "TODO".to_string(),
            // TODO
            picture: "TODO".to_string(),
            website: None,
            email: env!("TESTMAIL").to_string(),
            gender: Gender::Other,
            birthdate: "".to_string(),
            zoneinfo: "Europe/Berlin".to_string(),
            locale: "de".to_string(),
            phone_number: None,
            password: "&@%*gokwg&wkf[rup[o1234".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestSuite;
    use axum::http::header::AUTHORIZATION;
    use google_authenticator::GoogleAuthenticator;

    #[tokio::test]
    async fn test_signup() {
        // start the suite
        let (connector, _) = TestSuite::start().await;

        // send the request
        let content = SignupRequest::default();
        let response = connector.post("/auth/signup").json(&content).send().await;
        assert_eq!(response.status(), StatusCode::CREATED);

        // parse the body
        let body = response.json::<Client>().await;
        assert_eq!(content.nickname, body.nickname().clone());
    }

    #[tokio::test]
    async fn test_login() {
        // init suite
        let suite = TestSuite::new().await;

        // build the body
        let body = AuthenticationRequest::builder()
            .nickname("dfclient".into())
            .password("password".into())
            .token(None)
            .build();

        // send the request
        let response = suite.connector.post("/auth/login").json(&body).send().await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        // init suite
        let suite = TestSuite::new().await;

        // build the body
        let body = AuthenticationRequest::builder()
            .nickname("client".into())
            .password("password".into())
            .token(None)
            .build();

        // send the request
        let response = suite.connector.post("/auth/login").json(&body).send().await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        // init suite
        let suite = TestSuite::new().await;

        // build the body
        let body = AuthenticationRequest::builder()
            .nickname("dfclient".into())
            .password("wdwad".into())
            .token(None)
            .build();

        // send the request
        let response = suite.connector.post("/auth/login").json(&body).send().await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_password_change() {
        let suite = TestSuite::new().await;
        let authorization = suite.authenticate("dfclient", "password").await;

        // build the body
        let password = "658t7igGyuAhi@ljoeWADrfp%";
        let body = UpdatePassword {
            password: password.to_string(),
        };

        // send the request
        let response = suite
            .connector
            .put("/auth/password")
            .json(&body)
            .header(AUTHORIZATION, authorization)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        // relogin with the new password (would panic on failure)
        suite.authenticate("dfclient", password).await;
    }

    #[tokio::test]
    #[should_panic]
    async fn test_activate_totp() {
        let suite = TestSuite::new().await;
        let authorization = suite.authenticate("dfclient", "password").await;

        // build the body
        let body = ActivateTOTP {
            token: GoogleAuthenticator::new()
                .get_code(suite.authentication_data.secret().as_str(), 0)
                .unwrap(),
        };
        let response = suite
            .connector
            .post("/auth/totp")
            .json(&body)
            .header(AUTHORIZATION, authorization)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);

        // should panic here
        suite.authenticate("dfclient", "password").await;
    }
}
