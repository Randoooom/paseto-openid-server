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

use rbatis::rbatis::Rbatis;
use std::sync::Arc;
use tokio::sync::Mutex;

pub mod client;

/// The connection wrapped into mutex and arc
pub type ConnectionPointer = Arc<Mutex<Rbatis>>;

/// Establish the postgres connection with the env vars
pub async fn establish_connection() -> Rbatis {
    //  init orm
    let rbatis = Rbatis::new();
    // link to the database
    rbatis
        .link(std::env::var("DATABASE_URL").unwrap().as_str())
        .await
        .expect("Establish postgres connection");

    // init the database
    let sql = include_str!("up.sql");
    rbatis.exec(sql, vec![]).await.unwrap();

    rbatis
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection() {
        // would panic here on failure, because of the unwraps
        let _ = establish_connection().await;
    }
}
