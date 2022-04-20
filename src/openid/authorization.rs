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

// /// Space-delimited, case-sensitive list of ASCII string values that specifies whether the
// /// Authorization Server prompts the End-User for reauthentication and consent.
// pub enum Prompt {
//     /// The Authorization Server MUST NOT display any authentication or consent user
//     /// interface pages. An error is returned if an End-User is not already authenticated or the
//     /// Client does not have pre-configured consent for the requested Claims or does not fulfill
//     /// other conditions for processing the request. The error code will typically be `login_required`,
//     /// `interaction_required`. This can be used as a method to check
//     /// for existing authentication and/or consent.
//     None,
//     /// The Authorization Server SHOULD prompt the End-User for reauthentication. If it cannot
//     /// reauthenticate the End-User, it MUST return an error, typically `login_required`.
//     Login,
//     /// The Authorization Server SHOULD prompt the End-User for consent before returning information
//     /// to the Client. If it cannot obtain consent, it MUST return an error, typically `consent_required`.
//     Consent,
//     /// The Authorization Server SHOULD prompt the End-User to select a user account.
//     /// This enables an End-User who has multiple accounts at the Authorization Server to select
//     /// amongst the multiple accounts that they might have current sessions for. If it cannot
//     /// obtain an account selection choice made by the End-User, it MUST return an error,
//     /// typically `account_selection_required`.
//     SelectAccount,
// }

// /// ASCII [RFC20] string value that specifies how the Authorization Server displays the authentication
// /// and consent user interface pages to the End-User.
// pub enum Display {
//     /// The Authorization Server SHOULD display the authentication and consent UI consistent with a
//     /// full User Agent page view. If the display parameter is not specified,
//     /// this is the default display mode.
//     Page,
//     /// The Authorization Server SHOULD display the authentication and consent UI consistent with
//     /// a popup User Agent window. The popup User Agent window should be of an appropriate size for
//     /// a login-focused dialog and should not obscure the entire window that it is popping up over.
//     Popup,
//     /// The Authorization Server SHOULD display the authentication and consent UI consistent
//     /// with a device that leverages a touch interface.
//     Touch,
//     /// The Authorization Server SHOULD display the authentication and consent UI consistent with
//     /// a "feature phone" type display.
//     Wap,
// }

pub struct TokenSigner {
    private_key: Key<64>,
    public_key: Key<32>,
}

impl TokenSigner {
    /// Init a new instance of the TokenSigner
    pub fn new() -> Result<Self, String> {
        // This whole section could be much cleaner, but the 32byte key has to be transformed
        // into the 64byte ec signature key manually

        // load the keys
        let private_key_raw = PKey::private_key_from_pem(include_bytes!("../../private_key.pem"))
            .unwrap()
            // convert to raw
            .raw_private_key()
            .unwrap();
        let public_key_raw = PKey::public_key_from_pem(include_bytes!("../../public_key.pem"))
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

        // construct
        Ok(Self {
            public_key,
            private_key,
        })
    }

    /// Sign a new PASETO-Token with the given sub
    pub fn sign(&self, sub: &Uuid) -> String {
        // build private key
        let private_key =
            PasetoAsymmetricPrivateKey::<V4, Public>::from(self.private_key.as_slice());
        // build expiry
        let expiry = Utc::now() + Duration::minutes(5);

        // sign the token
        PasetoBuilder::<V4, Public>::default()
            .set_claim(CustomClaim::try_from(("uuid", sub.to_string())).unwrap())
            .set_claim(ExpirationClaim::try_from(expiry.to_rfc3339()).unwrap())
            .build(&private_key)
            .unwrap()
    }
}

lazy_static! {
    pub static ref TOKENSIGNER: TokenSigner = TokenSigner::new().unwrap();
}
