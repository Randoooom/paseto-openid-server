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

use chrono::{DateTime, Duration, Utc};
use rbatis::Uuid;
use std::collections::HashMap;

pub struct Session {
    sub: Uuid,
    started: DateTime<Utc>,
}

impl Session {
    /// Create a new session instance from the given sub
    pub fn new(sub: Uuid) -> Self {
        Self {
            sub,
            started: Utc::now(),
        }
    }

    /// Checks if the given session is still active (exp)
    pub fn is_active(&self) -> bool {
        // calculate the exp timestamp
        let exp = self.started + Duration::minutes(crate::LOCAL_SESSION_LENGTH.clone() as i64);
        // get the current
        let current = Utc::now();

        // validate
        return exp.timestamp() >= current.timestamp();
    }
}

pub struct AuthHandler {
    sessions: HashMap<String, Session>,
}

impl AuthHandler {
    /// Create new AuthHandler instance
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Register a new session for the given sub
    pub fn start_session(&mut self, sub: Uuid) -> String {
        // generate the sessionID
        let session_id = Self::create_session_id();
        // generate the sessions
        let session = Session::new(sub);

        // save the session into the HashMap
        self.sessions.insert(session_id.clone(), session);
        // return the sessionID
        session_id
    }

    /// Generate a new random sessionID
    fn create_session_id() -> String {
        // generate random bytes
        let mut bytes = [0u8; 32];
        openssl::rand::rand_bytes(&mut bytes).unwrap();

        // encode in base64
        openssl::base64::encode_block(bytes.as_slice())
    }
}
