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
use crate::locator::LocatorPointer;
use crate::openid::authorization::GrantTokenRequest;
use axum::extract::Form;
use axum::response::IntoResponse;
use axum::Extension;

pub async fn grant_token(
    Extension(locator): Extension<LocatorPointer>,
    Form(request): Form<GrantTokenRequest>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    // lock
    let mut locator = locator.lock().await;

    // handle the request
    locator.openid_mut().grant_token(request, &client)
}

#[cfg(test)]
mod tests {
    use crate::openid::authorization::{AuthorizationRequest, GrantTokenRequest, TokenResponse};
    use crate::tests::TestSuite;
    use axum::http::header::AUTHORIZATION;
    use reqwest::{StatusCode, Url};

    #[tokio::test]
    async fn test_token_grant() {
        let suite = TestSuite::new().await;
        let authorization = suite.authenticate("dfclient", "password").await;

        // get the code
        let code = {
            let body = AuthorizationRequest {
                response_type: "code".to_string(),
                client_id: suite.client.sub().to_string(),
                scope: "openid".to_string(),
                redirect_uri: "https://example.com/callback/".to_string(),
                state: None,
            };

            let response = suite
                .connector
                .post("/authorize")
                .form(&body)
                .header(AUTHORIZATION, &authorization)
                .send()
                .await;
            assert_eq!(response.status(), StatusCode::OK);
            let data = response.json::<serde_json::Value>().await;
            let uri = data.get("uri").unwrap().as_str().unwrap();
            // extract the code
            let uri = Url::parse(uri).unwrap();
            let (_, code) = uri.query_pairs().next().unwrap();

            // convert to string
            code.to_string()
        };

        // make the token request
        let body = GrantTokenRequest { code, state: None };
        let response = suite
            .connector
            .post("/token")
            .header(AUTHORIZATION, &authorization)
            .form(&body)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        // would panic on fail
        response.json::<TokenResponse>().await;
    }
}
