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

use crate::app;
use crate::database::client::{Address, Client, ClientAuthenticationData};
use crate::database::establish_connection;
use axum::http::StatusCode;
use axum_test_helper::TestClient;
use rbatis::crud::CRUD;
use rbatis::rbatis::Rbatis;

#[cfg(test)]
pub struct TestSuite {
    pub client: Client,
    pub connection: Rbatis,
    pub connector: TestClient,
    pub authentication_data: ClientAuthenticationData,
}

#[cfg(test)]
impl TestSuite {
    pub async fn start() -> (TestClient, Rbatis) {
        // build the testClient
        let connector = TestClient::new(app().await);
        // connect to the database
        let connection = establish_connection().await;

        // reset the database
        Self::reset_database(&connection).await;

        (connector, connection)
    }

    pub async fn reset_database(connection: &Rbatis) {
        // drop all tables
        let sql = include_str!("database/drop.sql");
        connection.exec(sql, vec![]).await.unwrap();
    }

    /// Create a new suite
    pub async fn new() -> Self {
        // setup
        let (connector, connection) = Self::start().await;

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
            .street_address("Willy-Brandt-Straße 1")
            .formatted("Willy-Brandt-Straße 1 10557 Berlin")
            .build();

        // save them all
        connection.save(&client, &[]).await.unwrap();
        connection.save(&auth, &[]).await.unwrap();
        connection.save(&address, &[]).await.unwrap();

        Self {
            client,
            connection,
            connector,
            authentication_data: auth,
        }
    }

    pub async fn authenticate(&self, nickname: &str, password: &str) -> String {
        // send the authentication request
        let response = self
            .connector
            .post("/auth/login")
            .json(&json!({"nickname": nickname,
            "password": password}))
            .send()
            .await;

        // validate the response
        assert_eq!(response.status(), StatusCode::OK);

        // parse the body
        let body = response.json::<serde_json::Value>().await;
        // get the session_id
        let session_id = body.get("session_id").unwrap();

        // convert
        session_id.as_str().unwrap().to_string()
    }
}
