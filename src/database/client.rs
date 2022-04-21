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

use crate::ConnectionPointer;
use argon2::{self};
use google_authenticator::GoogleAuthenticator;
use rbatis::crud::CRUD;
use rbatis::{TimestampZ, Uuid};

#[derive(Clone, Deserialize, Serialize, Debug)]
pub enum Gender {
    Male,
    Female,
    Other,
}

/// Covers https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
#[derive(TypedBuilder, Clone, Debug, Getters)]
#[crud_table(id_name: "sub" | id_type: "Uuid" | table_name: "clients")]
#[get = "pub"]
#[builder(field_defaults(setter(into)))]
pub struct Client {
    /// the unique value for identification
    #[builder(default_code = r#"Uuid::new()"#)]
    sub: Uuid,
    /// The full name in displayable form
    name: String,
    /// The first name(s) of the user
    given_name: String,
    /// The last name
    family_name: String,
    /// The middle name(s) of the user
    middle_name: Option<String>,
    /// The nickname of the user (unique)
    nickname: String,
    /// The preffered name of the user (must not be unique)
    preferred_username: String,
    /// The url to the data of the user
    profile: String,
    /// The url to a picture of the user?
    picture: String,
    /// The website or blog of the user
    website: Option<String>,
    /// The email of the user
    email: String,
    /// is the email verified?
    #[builder(default = false)]
    email_verified: bool,
    /// the gender
    gender: Gender,
    /// The birthdate as iso
    birthdate: String,
    /// the timezone
    zoneinfo: String,
    /// the users locale
    locale: String,
    /// The phone number of the user
    phone_number: Option<String>,
    /// Not implemented yet
    #[builder(default = false)]
    phone_number_verified: bool,
    /// last updated timestamp
    #[builder(default_code = r#"TimestampZ::now()"#)]
    updated_at: TimestampZ,
}

impl Client {
    /// Get the client by the nickname
    pub async fn from_nickname(
        nickname: &str,
        connection: &ConnectionPointer,
    ) -> rbatis::Result<Option<Self>> {
        // lock the connection
        let locked = connection.lock().await;

        // collect
        locked.fetch_by_column("nickname", nickname).await
    }

    /// Get the associated address object of the user
    pub async fn address(&self, connection: &ConnectionPointer) -> rbatis::Result<Option<Address>> {
        // lock the connection
        let locked = connection.lock().await;

        // collect
        locked.fetch_by_column("client", self.sub.clone()).await
    }

    // Get the associated authentication data object of the user
    pub async fn authentication_data(
        &self,
        connection: &ConnectionPointer,
    ) -> rbatis::Result<Option<ClientAuthenticationData>> {
        // lock the connection
        let locked = connection.lock().await;

        // collect
        locked.fetch_by_column("client", self.sub.clone()).await
    }
}

#[derive(TypedBuilder, Clone, Debug, Getters)]
#[crud_table(id_name: "uuid" | id_type: "Uuid" | table_name: "addresses")]
#[get = "pub"]
#[builder(field_defaults(setter(into)))]
pub struct Address {
    /// the identifier of the address
    #[builder(default_code = r#"Uuid::new()"#)]
    uuid: Uuid,
    /// Displayable formatted address
    formatted: String,
    /// Full street address
    street_address: String,
    /// City or locality
    locality: String,
    /// State / province etc.
    region: String,
    /// Zip or postal code
    postal_code: String,
    /// The country
    country: String,
    /// the associated client
    client: Uuid,
}

fn hash_password(password: String) -> String {
    // build the argon config
    let config = argon2::Config {
        variant: argon2::Variant::Argon2d,
        ..Default::default()
    };
    // gen the salt
    let mut salt = [0u8; 16];
    // fill
    openssl::rand::rand_bytes(&mut salt).unwrap();

    // hash the password
    argon2::hash_encoded(password.as_bytes(), salt.as_slice(), &config).unwrap()
}

#[derive(TypedBuilder, Clone, Debug, Getters)]
#[crud_table(id_name: "uuid" | id_type: "Uuid" | table_name: "client_authentication_data")]
#[get = "pub"]
#[builder(field_defaults(setter(into)))]
pub struct ClientAuthenticationData {
    /// the unique identifier for the data
    #[builder(default_code = r#"Uuid::new()"#)]
    uuid: Uuid,
    /// The argon2d hashed password
    #[builder(setter(!strip_option, transform = |password: String| hash_password(password)))]
    password: String,
    /// The TOTP secret (base32 encoded)
    #[builder(default = None)]
    secret: Option<String>,
    /// The last registered login / grant
    #[builder(default_code = r#"TimestampZ::now()"#)]
    last_login: TimestampZ,
    /// the associated client
    client: Uuid,
}

impl ClientAuthenticationData {
    /// Validate the given token with the totp secret of the client
    pub fn validate_totp(&self, token: &str) -> bool {
        // init the instance
        let totp = GoogleAuthenticator::new();

        // verify
        totp.verify_code(self.secret.as_ref().unwrap().as_str(), token, 30, 0)
    }

    /// Authenticate the login for the client based on the given password (and totp, if enabled)
    pub fn login(&self, password: &str, token: Option<&str>) -> bool {
        // verify the password with the hash
        let matches =
            argon2::verify_encoded(self.password.as_str(), password.as_bytes()).unwrap_or(false);

        if matches {
            // check for totp activated (secret exists or not)
            if self.secret.is_some() {
                // check the input
                if token.is_none() {
                    return false;
                }

                // unwrap the option
                let token = token.unwrap();
                // validate the totp
                if !self.validate_totp(token) {
                    return false;
                }
            }

            return true;
        }
        false
    }
}

#[derive(TypedBuilder, Clone, Debug, Getters)]
#[crud_table(id_name: "uuid" | id_type: "Uuid" | table_name: "client_verification_tokens")]
#[get = "pub"]
#[builder(field_defaults(setter(into)))]
pub struct ClientVerificationToken {
    /// The token as such and the identification
    #[builder(default_code = r#"Uuid::new()"#)]
    uuid: Uuid,
    /// the associated client
    client: Uuid,
}
