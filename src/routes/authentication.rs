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

use crate::database::client::Client;
use crate::openid::authorization::TOKENSIGNER;
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

#[post("/login", data = "<data>")]
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
                let token = TOKENSIGNER.sign(client.sub());

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
