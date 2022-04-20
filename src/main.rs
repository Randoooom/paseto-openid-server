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
extern crate rocket;
#[macro_use]
extern crate getset;
#[macro_use]
extern crate typed_builder;
extern crate argon2;
#[macro_use]
extern crate rbatis;
#[macro_use]
extern crate lazy_static;

use crate::database::ConnectionPointer;
use crate::paseto::TokenSigner;
use rocket::http::Method;
use std::sync::Arc;
use tokio::sync::Mutex;

mod database;
mod logger;
mod openid;
mod paseto;
mod responder;
mod routes;

#[derive(Getters)]
#[get = "pub"]
pub struct Locator {
    connection: ConnectionPointer,
    // the paseto instanc
    paseto: TokenSigner,
}

impl Locator {
    pub async fn new() -> Self {
        // establish the connection
        let connection = database::establish_connection().await;
        // create new instance of the signer
        let paseto = TokenSigner::new();

        Self { connection, paseto }
    }
}

pub type LocatorPointer = Arc<Mutex<Locator>>;

#[tokio::main]
async fn main() {
    // set the logging format
    log::set_logger(&logger::LOGGER)
        .map(|()| log::set_max_level(log::LevelFilter::max()))
        .unwrap();
    // init dotenv
    dotenv::dotenv().expect("Use the .env file");

    // load the cors fairing
    let cors = {
        // load the allowed origins from env
        let origins = std::env::var("ALLOWED_ORIGINS").unwrap();
        // split
        let origins = origins.split_whitespace().collect::<Vec<&str>>();
        // setup the cors origins
        let allowed_origins = rocket_cors::AllowedOrigins::some_exact(origins.as_slice());
        // cors options
        let cors_options = rocket_cors::CorsOptions {
            allowed_origins,
            allowed_methods: vec![
                Method::Get,
                Method::Post,
                Method::Put,
                Method::Delete,
                Method::Options,
                Method::Head,
            ]
            .into_iter()
            .map(From::from)
            .collect(),
            allow_credentials: true,
            ..Default::default()
        };

        cors_options.to_cors().unwrap()
    };

    // init the locator
    let locator = Locator::new().await;

    // build the rocket
    rocket::build()
        .mount("/", routes![routes::authentication::post_login])
        // attach cors
        .attach(cors)
        // manage the locator
        .manage(Arc::new(Mutex::new(locator)))
        // launch it
        .launch()
        .await
        .unwrap();
}
