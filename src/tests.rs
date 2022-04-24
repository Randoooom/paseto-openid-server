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

use crate::database::client::{Address, Client, ClientAuthenticationData};
use crate::database::establish_connection;
use axum::body::BoxBody;
use hyper::Body;
use rbatis::crud::CRUD;
use rbatis::rbatis::Rbatis;
use serde::de::DeserializeOwned;
use serde::Serialize;

#[cfg(test)]
pub struct TestSuite {
    client: Client,
    connection: Rbatis,
}

#[cfg(test)]
impl TestSuite {
    pub async fn reset_database(connection: &Rbatis) {
        // drop all tables
        let sql = include_str!("database/drop.sql");
        connection.exec(sql, vec![]).await.unwrap();
    }

    /// Create a new suite
    pub async fn new() -> Self {
        // connect to the database
        let connection = establish_connection().await;
        // reset the database
        Self::reset_database(&connection).await;

        // create a new client
        let client = Client::default();
        // create the auth data
        let auth = ClientAuthenticationData::builder()
            .password("password".into())
            .client(client.sub().clone())
            .build();
        // create some random address
        let address = Address::builder()
            .client(client.sub().clone())
            .country("Germany")
            .locality("Berlin")
            .region("Berlin")
            .postal_code("10557")
            .street_address(" Willy-Brandt-Straße 1")
            .formatted("Willy-Brandt-Straße 1 10557 Berlin")
            .build();

        // save them all
        connection.save(&client, &[]).await.unwrap();
        connection.save(&auth, &[]).await.unwrap();
        connection.save(&address, &[]).await.unwrap();

        Self { client, connection }
    }

    pub async fn parse_body<T: DeserializeOwned>(body: BoxBody) -> T {
        let raw = hyper::body::to_bytes(body).await.unwrap();
        serde_json::from_slice::<T>(&raw).unwrap()
    }

    pub fn create_body<T: Serialize>(object: &T) -> Body {
        let raw = serde_json::to_vec(object).unwrap();
        Body::from(raw)
    }
}
