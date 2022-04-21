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

use crate::database::client::{Client, ClientAuthenticationData, Gender};
use crate::openid::verification::Verification;
use crate::responder::ApiResponse;
use crate::LocatorPointer;
use rocket::http::{Cookie, CookieJar, SameSite, Status};
use rocket::serde::json::Json;
use rocket::State;

#[derive(Deserialize, Serialize)]
pub struct AuthenticationRequest {
    /// the username / nickname of the client
    nickname: String,
    /// the password
    password: String,
    /// the totp
    token: Option<String>,
}

#[derive(Deserialize, Serialize)]
pub struct AuthenticationResponse {
    /// the verification token
    token: String,
}

impl From<String> for AuthenticationResponse {
    fn from(token: String) -> AuthenticationResponse {
        Self { token }
    }
}

#[post("/auth/login", data = "<data>")]
pub async fn post_login(
    data: Json<AuthenticationRequest>,
    locator: &State<LocatorPointer>,
    cookies: &CookieJar<'_>,
) -> ApiResponse<AuthenticationResponse> {
    // lock the locator
    let locked = locator.lock().await;

    // get the client
    let client = Client::from_nickname(data.nickname.as_str(), &locked.connection)
        .await
        .unwrap();
    if let Some(client) = client {
        // get the auth data
        let authentication_data = client
            .authentication_data(&locked.connection)
            .await
            .unwrap();

        if let Some(authentication_data) = authentication_data {
            // authenticate
            if authentication_data.login(data.password.as_str(), data.token.as_deref()) {
                // sign the token
                let token = locked.paseto.sign(client.sub());

                // build the cookie
                let cookie = Cookie::build("X-ACCESS-TOKEN", &token)
                    .secure(true)
                    .same_site(SameSite::Strict)
                    .http_only(true)
                    .finish();
                // set the cookie
                cookies.add(cookie);

                // return the signed token
                return ApiResponse::data(Status::Ok, AuthenticationResponse::from(token));
            }
        }
    }

    // return 401
    ApiResponse::error(Status::Unauthorized, json!({"error": "Unauthorized"}))
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

#[post("/auth/signup", data = "<data>")]
pub async fn post_signup(
    data: Json<SignupRequest>,
    locator: &State<LocatorPointer>,
) -> ApiResponse<Client> {
    // lock the locator
    let locked = locator.lock().await;

    // verify the strength of the password
    if !Verification::password_strong_enough(data.password.as_str()) {
        return ApiResponse::error(
            Status::BadRequest,
            json!({"error": "Password not strong enough"}),
        );
    }
    // validate the email (check via regex)
    if !Verification::email_valid(data.email.as_str()) {
        return ApiResponse::error(Status::BadRequest, json!({"error": "Email not valid"}));
    }

    // build the client
    let client = Client::builder()
        .nickname(data.nickname)
        .birthdate(data.birthdate)
        .email(data.email)
        .family_name(data.family_name)
        .gender(data.gender)
        .given_name(data.given_name)
        .locale(data.locale)
        .middle_name(data.middle_name)
        .name(data.name)
        .phone_number(data.phone_number)
        .picture(data.picture)
        .preferred_username(data.preffered_username)
        .profile(data.profile)
        .website(data.website)
        .zoneinfo(data.zoneinfo)
        .build();

    // build the authentication data
    let auth_data = ClientAuthenticationData::builder()
        .client(client.sub().clone())
        .password(data.password)
        .build();

    // lock the connection
    let connection = locked.connection.lock().await;
    // save the data
    connection.save(&client, &[]).await.unwrap();
    connection.save(&auth_data, &[]).await.unwrap();

    // TODO: send confirmation and verification email
    ApiResponse::data(Status::Created, client)
}
