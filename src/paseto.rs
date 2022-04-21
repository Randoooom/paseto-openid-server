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

use chrono::{Duration, Utc};
use openssl::pkey::PKey;
use rbatis::Uuid;
use rusty_paseto::prelude::*;

pub struct TokenSigner {
    // for public
    private_key: Key<64>,
    public_key: Key<32>,
    // for local auth
    secret: Key<32>,
}

impl TokenSigner {
    /// Init a new instance of the TokenSigner
    pub fn new() -> Self {
        // This whole section could be much cleaner, but the 32byte key has to be transformed
        // into the 64byte ec signature key manually

        // load the keys
        let private_key_raw = PKey::private_key_from_pem(include_bytes!("../private_key.pem"))
            .unwrap()
            // convert to raw
            .raw_private_key()
            .unwrap();
        let public_key_raw = PKey::public_key_from_pem(include_bytes!("../public_key.pem"))
            .unwrap()
            // convert to raw
            .raw_public_key()
            .unwrap();

        // build the signature key
        let mut bytes: [u8; 64] = [0u8; 64];
        bytes[..32].copy_from_slice(private_key_raw.as_slice());
        bytes[32..].copy_from_slice(public_key_raw.as_slice());

        // setup the keys
        let public_key = Key::<32>::from(public_key_raw.as_slice());
        let private_key = Key::<64>::from(bytes);

        // generate the local secret
        let secret = Key::<32>::try_new_random().unwrap();

        // construct
        Self {
            public_key,
            private_key,
            secret,
        }
    }

    /// Sign a new PASETO-Token with the given sub for use over openid
    pub fn sign_public(&self, sub: &Uuid) -> String {
        // build private key
        let private_key =
            PasetoAsymmetricPrivateKey::<V4, Public>::from(self.private_key.as_slice());
        // build expiry
        let expiry = Utc::now() + Duration::minutes(5);
        // convert sub
        let sub = sub.to_string();

        // sign the token
        let result = PasetoBuilder::<V4, Public>::default()
            .set_claim(SubjectClaim::from(sub.as_str()))
            .set_claim(ExpirationClaim::try_from(expiry.to_rfc3339()).unwrap())
            .build(&private_key)
            .unwrap();
        result
    }

    /// Sign new PASETO local token for authentication inside the openid provider
    pub fn sign_local(&self, sub: &Uuid) -> String {
        // build key
        let key = PasetoSymmetricKey::<V4, Local>::from(self.secret.clone());
        // convert sub
        let sub = sub.to_string();

        // sign the token
        let result = PasetoBuilder::<V4, Local>::default()
            .set_claim(SubjectClaim::from(sub.as_str()))
            .build(&key)
            .unwrap();
        result
    }
}
