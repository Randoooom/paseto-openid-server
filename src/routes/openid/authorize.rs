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
use crate::openid::authorization::AuthorizationRequest;
use axum::extract::{Form, Query};
use axum::response::IntoResponse;
use axum::Extension;

pub async fn get_authorize(
    Query(request): Query<AuthorizationRequest>,
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    // lock
    let mut locator = locator.lock().await;

    // handle the request
    locator.openid_mut().grant_code(request, &client)
}

pub async fn post_authorize(
    Form(request): Form<AuthorizationRequest>,
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    // lock
    let mut locator = locator.lock().await;

    // handle the request
    locator.openid_mut().grant_code(request, &client)
}
