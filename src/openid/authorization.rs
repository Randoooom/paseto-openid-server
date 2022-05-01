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
use axum::response::{IntoResponse, Redirect};
use chrono::{DateTime, Duration, Utc};
use rbatis::Uuid;
use std::collections::HashMap;

pub struct AuthorizationRequest {
    response_type: String,
    client_id: String,
    /// "openid ..."
    scope: String,
    /// TODO: verify issuers from the database
    redirect_uri: String,
    state: Option<String>,
    nonce: String,
    // the other fields can be ignored because this is not relevant in the api
}

pub struct GrantTokenRequest {
    /// must match 'authorization_code'
    grant_type: String,
    /// the issued code
    code: String,
    // TODO: handle the uri
    redirect_uri: Option<String>,
    client_id: Option<String>,
}

pub struct Context {
    sub: Uuid,
    scope: String,
    created: DateTime<Utc>,
}

impl Context {
    pub fn new(sub: Uuid, scope: String) -> Self {
        Self {
            sub,
            scope,
            created: Utc::now(),
        }
    }

    pub fn is_valid(&self) -> bool {
        let exp = self.created + Duration::minutes(10);

        Utc::now() <= exp
    }
}

pub struct OpenIDAuthorization {
    /// the temporary saved codes with the associated client
    codes: HashMap<String, Context>,
}

impl OpenIDAuthorization {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }

    /// Authorize the request with the given data
    pub async fn grant_code(
        &mut self,
        request: AuthorizationRequest,
        client: &Client,
    ) -> impl IntoResponse {
        // generate the temporary code
        let mut code = &[0u8; 16];
        openssl::rand::rand_bytes(&mut code).unwrap();
        // encode as base64
        let code = openssl::base64::encode_block(code.as_bytes());

        // save into the map
        self.codes
            .insert(code, Context::new(client.sub().clone(), request.scope));
        // build the redirect_uri
        let uri = {
            let mut uri = request.redirect_uri;
            uri.push_str(format!("?code={}", code).as_str());

            if let Some(state) = request.state {
                uri.push_str(format!("&state={}", state).as_str());
            }

            uri
        };

        // return the redirect
        Redirect::to(uri.as_str())
    }

    pub async fn grant_token() -> impl IntoResponse {}
}
