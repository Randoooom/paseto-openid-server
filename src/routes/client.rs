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
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};

pub async fn post_delete(
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    // lock the locator
    let locked = locator.lock().await;
    // get the connection
    let connection = locked.connection().lock().await;

    // delete the client
    client.delete(&connection).await;
    (StatusCode::OK, Json(json!({"message": "Deleted"})))
}

#[cfg(test)]
mod tests {
    use crate::tests::TestSuite;
    use axum::http::header::AUTHORIZATION;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_delete() {
        let suite = TestSuite::new().await;
        // authenticate the default user
        let cookie = suite.authenticate("dfclient", "password").await;

        // send the request
        let response = suite
            .connector
            .post("/client/delete")
            .header(AUTHORIZATION, cookie)
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await,
            json!({"message": "Deleted"}).to_string()
        )
    }
}
