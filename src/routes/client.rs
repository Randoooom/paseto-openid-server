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

use crate::database::client::{Client, Gender};
use crate::locator::LocatorPointer;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use rbatis::crud::CRUD;

pub async fn post_delete(
    Extension(locator): Extension<LocatorPointer>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    // lock the locator
    let locked = locator.lock().await;

    // delete the client
    client.delete(locked.connection()).await;
    (StatusCode::OK, Json(json!({"message": "Deleted"})))
}

pub async fn get_me(Extension(client): Extension<Client>) -> impl IntoResponse {
    // return the client as json
    (StatusCode::OK, Json(client))
}

#[derive(Deserialize, Serialize)]
pub struct UpdateClient {
    name: String,
    given_name: String,
    family_name: String,
    middle_name: Option<String>,
    preferred_username: String,
    picture: String,
    gender: Gender,
    zoneinfo: String,
    locale: String,
}

/// Accepts only full client objects
pub async fn put_me(
    Extension(locator): Extension<LocatorPointer>,
    Json(data): Json<UpdateClient>,
    Extension(mut client): Extension<Client>,
) -> impl IntoResponse {
    // build the new client
    let client = client
        .set_name(data.name)
        .set_given_name(data.given_name)
        .set_family_name(data.family_name)
        .set_middle_name(data.middle_name)
        .set_preferred_username(data.preferred_username)
        .set_picture(data.picture)
        .set_gender(data.gender)
        .set_zoneinfo(data.zoneinfo)
        .set_locale(data.locale);

    // lock the connection
    let locator = locator.lock().await;
    // update the client
    locator
        .connection()
        .update_by_column("sub", client)
        .await
        .unwrap();

    (StatusCode::OK, Json(client.clone()))
}

#[derive(Deserialize, Serialize)]
pub struct UpdateAddress {
    formatted: String,
    street_address: String,
    locality: String,
    region: String,
    postal_code: String,
    country: String,
}

pub async fn put_address(
    Extension(locator): Extension<LocatorPointer>,
    Json(update): Json<UpdateAddress>,
    Extension(client): Extension<Client>,
) -> impl IntoResponse {
    // lock the locator
    let locator = locator.lock().await;
    let connection = locator.connection();

    // get the current address from the client
    let mut address = client.address(connection).await.unwrap().unwrap();
    // update it
    let address = address
        .set_formatted(update.formatted)
        .set_street_address(update.street_address)
        .set_locality(update.locality)
        .set_region(update.region)
        .set_postal_code(update.postal_code)
        .set_country(update.country);
    connection.update_by_column("uuid", address).await.unwrap();

    (StatusCode::OK, Json(address.clone()))
}

#[cfg(test)]
mod tests {
    use crate::database::client::{Address, Client};
    use crate::routes::client::{UpdateAddress, UpdateClient};
    use crate::tests::TestSuite;
    use axum::http::header::AUTHORIZATION;
    use axum::http::StatusCode;

    #[tokio::test]
    async fn test_delete() {
        let suite = TestSuite::new().await;
        // authenticate the default user
        let authorization = suite.authenticate("dfclient", "password").await;

        // send the request
        let response = suite
            .connector
            .post("/client/delete")
            .header(AUTHORIZATION, authorization)
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.text().await,
            json!({"message": "Deleted"}).to_string()
        )
    }

    #[tokio::test]
    async fn test_me() {
        let suite = TestSuite::new().await;
        // authenticate the default user
        let authorization = suite.authenticate("dfclient", "password").await;

        // send the request
        let response = suite
            .connector
            .get("/client/me")
            .header(AUTHORIZATION, authorization)
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.json::<Client>().await.sub(), suite.client.sub());
    }

    #[tokio::test]
    async fn test_put() {
        let suite = TestSuite::new().await;
        // authenticate the default user
        let authorization = suite.authenticate("dfclient", "password").await;

        // build the body
        let body = UpdateClient {
            name: "Changed".to_string(),
            given_name: suite.client.given_name().clone(),
            family_name: suite.client.family_name().clone(),
            middle_name: suite.client.middle_name().clone(),
            preferred_username: suite.client.preferred_username().clone(),
            picture: suite.client.picture().clone(),
            gender: suite.client.gender().clone(),
            zoneinfo: suite.client.zoneinfo().clone(),
            locale: suite.client.locale().clone(),
        };

        // send the request
        let response = suite
            .connector
            .put("/client/me")
            .header(AUTHORIZATION, &authorization)
            .json(&body)
            .send()
            .await;

        assert_eq!(response.status(), StatusCode::OK);
        let data = response.json::<Client>().await;
        assert_eq!(data.name().as_str(), "Changed");

        // get the me
        let response = suite
            .connector
            .get("/client/me")
            .header(AUTHORIZATION, authorization)
            .send()
            .await;
        assert_eq!(response.json::<Client>().await.name(), data.name())
    }

    #[tokio::test]
    async fn test_put_address() {
        let suite = TestSuite::new().await;
        // authenticate the default user
        let authorization = suite.authenticate("dfclient", "password").await;

        // build the body
        let body = UpdateAddress {
            formatted: "Hell Yea".to_string(),
            street_address: "".to_string(),
            locality: "".to_string(),
            region: "".to_string(),
            postal_code: "".to_string(),
            country: "".to_string(),
        };

        // send the request
        let response = suite
            .connector
            .put("/client/me/address")
            .json(&body)
            .header(AUTHORIZATION, authorization)
            .send()
            .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.json::<Address>().await.formatted().as_str(),
            "Hell Yea"
        );
    }
}
