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

use std::str::FromStr;

pub mod authorization;
pub mod verification;

#[derive(Clone, Debug)]
pub enum Scope {
    OpenId,
    Profile,
    Email,
    Address,
    Phone,
    Offline,
}

impl FromStr for Scope {
    type Err = ();

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.to_lowercase().as_str() {
            "openid" => Ok(Scope::OpenId),
            "profile" => Ok(Scope::Profile),
            "email" => Ok(Scope::Email),
            "address" => Ok(Scope::Address),
            "phone" => Ok(Scope::Phone),
            "offline" => Ok(Scope::Offline),
            _ => Err(()),
        }
    }
}

impl ToString for Scope {
    fn to_string(&self) -> String {
        match self {
            Scope::Address => String::from("address"),
            Scope::Email => String::from("email"),
            Scope::OpenId => String::from("openId"),
            Scope::Profile => String::from("profile"),
            Scope::Phone => String::from("phone"),
            Scope::Offline => String::from("offline"),
        }
    }
}
