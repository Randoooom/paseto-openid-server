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
use axum::middleware::Next;
use axum::response::IntoResponse;
use rbatis::crud::CRUD;

#[derive(Clone)]
pub struct SessionId(pub String);

pub async fn require_session<B>(mut request: Request<B>, next: Next<B>) -> impl IntoResponse {
    match request.headers().get(AUTHORIZATION).cloned() {
        Some(value) => {
            // get the id
            let session_id = value.to_str().unwrap();

            // get the locator and lock it
            let locator = request.extensions_mut().get::<LocatorPointer>().unwrap();
            let mut locator = locator.lock().await;

            // get the session
            if let Some(session) = locator.auth_mut().session_valid(session_id) {
                // fetch the client from the session
                let client: Client = locator
                    .connection()
                    .fetch_by_column("sub", session.sub())
                    .await
                    .unwrap();
                drop(locator);

                // set the client for the handler
                request.extensions_mut().insert(client);
                // set the session id
                request
                    .extensions_mut()
                    .insert(SessionId(session_id.to_string()));
                // set the session
                request.extensions_mut().insert(session.clone());

                // process next
                return next.run(request).await;
            }

            drop(locator);
            ResponseError::Unauthorized.into_response()
        }
        None => ResponseError::Unauthorized.into_response(),
    }
}
