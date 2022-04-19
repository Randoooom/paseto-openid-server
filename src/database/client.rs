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

use rbatis::{TimestampZ, Uuid};

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
    phone_number_verified: bool,
    /// last updated timestamp
    updated_at: TimestampZ,
}

#[derive(TypedBuilder, Clone, Debug, Getters)]
#[crud_table(id_name: "uuid" | id_type: "Uuid" | table_name: "addresses")]
#[get = "pub"]
#[builder(field_defaults(setter(into)))]
pub struct Address {
    /// the identifier of the address
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
