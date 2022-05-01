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

#[macro_use]
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate getset;
#[macro_use]
extern crate typed_builder;
extern crate argon2;
#[macro_use]
extern crate rbatis;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate thiserror;
#[macro_use]
extern crate async_trait;

use crate::middleware::require_session;
use axum::http::{header, Method};
use axum::middleware::from_fn;
use axum::{
    routing::{get, post, put},
    Extension, Router,
};
use std::net::SocketAddr;
use tower_http::cors::{CorsLayer, Origin};
use tower_http::trace::TraceLayer;

mod database;
mod error;
mod locator;
mod logger;
mod middleware;
mod openid;
mod routes;
#[cfg(test)]
mod tests;

lazy_static! {
    pub static ref ROOT: String = std::env::var("ROOT").unwrap();
    pub static ref TOTP_NAME: String = std::env::var("TOTP_NAME").unwrap();
    pub static ref LOCAL_SESSION_LENGTH: usize = std::env::var("LOCAL_SESSION_LENGTH")
        .unwrap()
        .parse()
        .unwrap();
}

#[tokio::main]
async fn main() {
    // set the logging format
    log::set_logger(&logger::LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::max()))
        .unwrap();
    // init dotenv
    dotenv::dotenv().expect("Use the .env file");

    // build the address
    let address = SocketAddr::from((
        [127, 0, 0, 1],
        std::env::var("PORT").unwrap().parse::<u16>().unwrap(),
    ));
    // run
    info!("Axum server listening on {}", address);
    axum::Server::bind(&address)
        .serve(app().await.into_make_service())
        .await
        .unwrap();
}

async fn app() -> Router {
    // init the locator
    let locator = locator::Locator::new().await;

    // build axum
    Router::new()
        .route("/auth/login", post(routes::authentication::post_login))
        .route("/auth/signup", post(routes::authentication::post_signup))
        .route(
            "/auth/password",
            put(routes::authentication::put_password).layer(from_fn(require_session)),
        )
        .route(
            "/auth/totp",
            post(routes::authentication::post_activate_totp)
                .get(routes::authentication::get_qr_code)
                .layer(from_fn(require_session)),
        )
        .route(
            "/auth/totp/disable",
            post(routes::authentication::post_disable_totp).layer(from_fn(require_session)),
        )
        .route(
            "/auth/logout",
            post(routes::authentication::post_logout).layer(from_fn(require_session)),
        )
        .route(
            "/client/me",
            get(routes::client::get_me)
                .put(routes::client::put_me)
                .layer(from_fn(require_session)),
        )
        .route(
            "/client/me/address",
            put(routes::client::put_address).layer(from_fn(require_session)),
        )
        .route(
            "/client/delete",
            post(routes::client::post_delete).layer(from_fn(require_session)),
        )
        // openid beginning routes here
        .route(
            "/authorize",
            post(routes::openid::authorize::post_authorize)
                .get(routes::openid::authorize::get_authorize)
                .layer(from_fn(require_session)),
        )
        .layer(Extension(locator))
        // enable CORS
        .layer(
            CorsLayer::new()
                .allow_origin(Origin::exact(ROOT.as_str().parse().unwrap()))
                .allow_methods(vec![
                    Method::GET,
                    Method::POST,
                    Method::PUT,
                    Method::DELETE,
                    Method::HEAD,
                    Method::OPTIONS,
                ])
                .allow_headers(vec![header::AUTHORIZATION, header::CONTENT_TYPE]),
        )
        // enable logging
        .layer(TraceLayer::new_for_http())
}
