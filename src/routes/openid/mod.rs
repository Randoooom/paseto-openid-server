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
use crate::error::ResponseError;
use crate::locator::LocatorPointer;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use rbatis::crud::CRUD;
use rbatis::Uuid;

pub mod authorize;
pub mod token;
pub mod userinfo;

#[derive(Deserialize, Serialize, Debug)]
pub struct ClientBasedLoginRequest {
    client_id: String,
    client_secret: String,
}

/// authenticate on client base for api's
pub async fn post_authenticate(
    Extension(locator): Extension<LocatorPointer>,
    Json(request): Json<ClientBasedLoginRequest>,
) -> impl IntoResponse {
    // lock
    let mut locator = locator.lock().await;
    let connection = locator.connection();

    // get the client
    match connection
        .fetch_by_column::<Client, _>("sub", Uuid::parse_str(request.client_id.as_str()).unwrap())
        .await
    {
        Ok(client) => {
            // get the authentication data
            let authentication_data = client
                .authentication_data(connection)
                .await
                .unwrap()
                .unwrap();
            // validate the secret
            if !authentication_data.secret().eq(&request.client_secret) {
                return Err(ResponseError::Unauthorized);
            }

            // start the session
            let session = locator.auth_mut().start_session(client.sub().clone());

            Ok((StatusCode::OK, Json(json!({ "session_id": session }))))
        }
        Err(_) => Err(ResponseError::Unauthorized),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::TestSuite;

    #[tokio::test]
    async fn test_authenticate() {
        let suite = TestSuite::new().await;

        let body = ClientBasedLoginRequest {
            client_id: suite.client.sub().to_string(),
            client_secret: suite.authentication_data.secret().clone(),
        };
        let response = suite.connector.post("/auth").json(&body).send().await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
