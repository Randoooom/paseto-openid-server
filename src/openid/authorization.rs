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
use crate::paseto::TokenSigner;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect};
use axum::Json;
use chrono::{DateTime, Duration, Utc};
use rbatis::Uuid;
use std::collections::HashMap;

#[derive(Deserialize, Serialize)]
pub struct AuthorizationRequest {
    pub response_type: String,
    pub client_id: String,
    /// "openid ..."
    pub scope: String,
    /// TODO: verify issuers from the database
    pub redirect_uri: String,
    pub state: Option<String>,
    // the other fields can be ignored because this is not relevant in the api
}

#[derive(Deserialize, Serialize, Debug)]
pub struct GrantTokenRequest {
    // not needed with openid
    // must match 'authorization_code'
    // grant_type: String,
    /// the issued code
    pub(crate) code: String,
    // not needed with openid
    // redirect_uri: Option<String>,
    // client_id: Option<String>,
    pub(crate) state: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct TokenResponse {
    /// the token for the userinfo endpoint
    access_token: String,
    refresh_token: String,
    // "Bearer"
    token_type: String,
    expires_in: String,
    // paseto v4.public token
    id_token: String,
}

#[derive(Setters, Clone, Debug, Getters)]
#[set = "pub"]
#[get = "pub"]
pub struct Context {
    sub: Uuid,
    scope: String,
    state: Option<String>,
    created: DateTime<Utc>,
}

impl Context {
    pub fn new(sub: Uuid, scope: String, state: Option<String>) -> Self {
        Self {
            sub,
            scope,
            state,
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
    tokens: HashMap<String, Context>,
}

impl OpenIDAuthorization {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
            tokens: HashMap::new(),
        }
    }

    /// Authorize the request with the given data
    pub fn grant_code(
        &mut self,
        request: AuthorizationRequest,
        client: &Client,
    ) -> impl IntoResponse {
        // generate the temporary code
        let mut code = [0u8; 16];
        openssl::rand::rand_bytes(&mut code).unwrap();
        // encode as base64
        let code = openssl::base64::encode_block(code.as_slice());

        // save into the map
        self.codes.insert(
            code.clone(),
            Context::new(client.sub().clone(), request.scope, request.state.clone()),
        );
        // build the redirect_uri
        let uri = {
            let mut uri = request.redirect_uri;
            uri.push_str(format!("?code={}", code).as_str());

            if let Some(state) = request.state {
                uri.push_str(format!("&state={}", state).as_str());
            }

            uri
        };

        // because we do can not catch the redirect in the tests we make this
        cfg_if! {
            if #[cfg(test)] {
                // return the uri as json value
                return (StatusCode::OK, Json(json!({"uri": uri})));
            } else {
                // return the redirect
                return Redirect::to(uri.as_str());
            }
        }
    }

    /// Convert the given temporary code into a access token (PASETO v4.public)
    pub fn grant_token(
        &mut self,
        request: GrantTokenRequest,
        client: &Client,
    ) -> impl IntoResponse {
        // get the context
        match self.codes.get(request.code.as_str()) {
            Some(context) => {
                // verify the context
                if !context.is_valid() {
                    // remove the context
                    self.codes.remove(request.code.as_str());

                    return Err(ResponseError::Unauthorized);
                }

                // generate a access_token for the userinfo endpoint
                let mut access_token = [0u8; 32];
                openssl::rand::rand_bytes(&mut access_token).unwrap();
                // encode as base64
                let access_token = openssl::base64::encode_block(access_token.as_slice());

                // clone the context
                let mut context = context.clone();
                // update the created
                context.set_created(Utc::now());
                // sign the id_token
                let signer = TokenSigner::new();
                let id_token = signer.sign(client.sub(), context.scope.clone());

                // save as access_token into the map
                self.tokens.insert(access_token.clone(), context);
                // revoke the code
                self.codes.remove(request.code.as_str());

                // build the response
                Ok((
                    StatusCode::OK,
                    Json(TokenResponse {
                        access_token,
                        refresh_token: "".to_string(),
                        token_type: String::from("Bearer"),
                        expires_in: String::from("3600"),
                        id_token,
                    }),
                ))
            }
            None => Err(ResponseError::Unauthorized),
        }
    }

    pub fn token_valid(&mut self, token: &str) -> Option<Context> {
        // get the context
        match self.tokens.get(token) {
            Some(context) => {
                // validate the context
                if context.is_valid() {
                    return Some(context.clone());
                }

                // remove it
                self.tokens.remove(token)
            }
            None => None,
        }
    }
}
