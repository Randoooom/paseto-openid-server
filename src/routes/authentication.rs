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

use crate::database::client::{Client, ClientAuthenticationData, ClientVerificationToken, Gender};
use crate::error::ResponseError;
use crate::locator::mail::MailOptions;
use crate::locator::LocatorPointer;
use crate::middleware::SessionId;
use crate::openid::verification::Verification;
use crate::ROOT;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
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
    cookies: CookieJar,
) -> impl IntoResponse {
    // lock the locator
    let mut locked = locator.lock().await;
    // lock the connection
    let connection = locked.connection().lock().await;

    // get the client
    let client = Client::from_nickname(data.nickname.as_str(), &connection)
        .await
        .unwrap();
    if let Some(client) = client {
        // get the auth data
        let authentication_data = client.authentication_data(&connection).await.unwrap();
        // unlock the connection
        drop(connection);

        if let Some(authentication_data) = authentication_data {
            // authenticate
            if authentication_data.login(data.password.as_str(), data.token.as_deref()) {
                // start the session
                let token = locked.auth_mut().start_session(client.sub().clone());

                // build the cookie
                let cookie = Cookie::build("session_id", token.clone())
                    .secure(true)
                    .same_site(SameSite::Strict)
                    .http_only(true)
                    .finish();
                // set the cookie
                let cookies = cookies.add(cookie);

                // return the signed token
                return Ok((StatusCode::OK, cookies, Json(json!({ "token": token }))));
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

    // lock the connection
    let connection = locked.connection().lock().await;
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
    cookies: CookieJar,
) -> impl IntoResponse {
    // lock the locator
    let mut locked = locator.lock().await;

    // end the session
    locked.auth_mut().end_session(session_id.0.as_str());

    // get the cookie
    let cookie = cookies.get(session_id.0.as_str()).unwrap().clone();
    // remove the cookie
    let cookies = cookies.remove(cookie);

    (StatusCode::OK, cookies)
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
    use crate::app;
    use crate::database::establish_connection;
    use crate::tests::TestSuite;
    use axum::body::Body;
    use axum::http::header::CONTENT_TYPE;
    use axum::http::{Method, Request};
    use hyper::header::SET_COOKIE;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_signup() {
        let connection = establish_connection().await;
        // reset the database
        TestSuite::reset_database(&connection).await;

        // send the request
        let content = SignupRequest::default();
        let response = app()
            .await
            .oneshot(
                Request::builder()
                    .uri("/auth/signup")
                    .method(Method::POST)
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::from(serde_json::to_vec(&content).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);

        // parse the body
        let body = TestSuite::parse_body::<Client>(response.into_body()).await;
        assert_eq!(content.nickname, body.nickname().clone());
    }

    #[tokio::test]
    async fn test_login() {
        // init suite
        let _suite = TestSuite::new().await;

        // build the body
        let body = TestSuite::create_body(
            &AuthenticationRequest::builder()
                .nickname("dfclient".into())
                .password("password".into())
                .token(None)
                .build(),
        );

        // send the request
        let response = app()
            .await
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // the body can be ignored because it is just a session id and it is the same as the cookie
        let cookie = response.headers().get(SET_COOKIE).unwrap();
        let cookie = Cookie::parse(cookie.to_str().unwrap()).unwrap();
        assert_eq!(cookie.name(), "session_id");
        assert!(cookie.http_only().unwrap());
        assert!(cookie.secure().unwrap());
    }

    #[tokio::test]
    async fn test_login_user_not_found() {
        // init suite
        let _suite = TestSuite::new().await;

        // build the body
        let body = TestSuite::create_body(
            &AuthenticationRequest::builder()
                .nickname("client".into())
                .password("password".into())
                .token(None)
                .build(),
        );

        // send the request
        let response = app()
            .await
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_login_invalid_password() {
        // init suite
        let _suite = TestSuite::new().await;

        // build the body
        let body = TestSuite::create_body(
            &AuthenticationRequest::builder()
                .nickname("dfclient".into())
                .password("wdwad".into())
                .token(None)
                .build(),
        );

        // TODO: We may can simplify the following stacked code on sometime
        // send the request
        let response = app()
            .await
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/auth/login")
                    .header(CONTENT_TYPE, "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
