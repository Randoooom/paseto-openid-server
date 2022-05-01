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
use axum::http::header::AUTHORIZATION;
use axum::http::Request;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use rbatis::crud::CRUD;

pub async fn get_userinfo<B>(
    Extension(locator): Extension<LocatorPointer>,
    request: Request<B>,
) -> impl IntoResponse {
    // lock
    let mut locator = locator.lock().await;
    // parse the header
    match request.headers().get(AUTHORIZATION) {
        Some(header) => {
            // parse the token (split bearer of)
            let mut split = header.to_str().unwrap().split_whitespace();
            let token = split.last().unwrap();

            // validate the token
            if let Some(context) = locator.openid_mut().token_valid(token) {
                // get the client
                let client = locator
                    .connection()
                    .fetch_by_column::<Client, _>("sub", context.sub())
                    .await
                    .unwrap();

                // TODO: handle the scopes
                return Ok(Json(client));
            }
            Err(ResponseError::Unauthorized)
        }
        None => Err(ResponseError::Unauthorized),
    }
}
