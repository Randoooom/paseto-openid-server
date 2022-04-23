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

use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::transport::smtp::response::Response;
use lettre::transport::smtp::Error;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

pub struct MailSender {
    username: String,
    password: String,
    host: String,
}

#[derive(TypedBuilder)]
pub struct MailOptions {
    to: String,
    subject: String,
    content: String,
}

impl MailSender {
    /// Create new MailSender
    /// This reads all necessary data from the env file
    pub fn new() -> Self {
        Self {
            username: std::env::var("SMTP_USER").unwrap(),
            password: std::env::var("SMTP_PASSWORD").unwrap(),
            host: std::env::var("SMTP_HOST").unwrap(),
        }
    }

    /// Sends an email with the given data
    pub async fn send(&self, options: MailOptions) -> Result<Response, Error> {
        // build the message
        let message = Message::builder()
            .from(self.username.parse().unwrap())
            .to(options.to.parse().unwrap())
            .subject(options.subject)
            .header(ContentType::TEXT_HTML)
            .body(options.content)
            .unwrap();

        // connect
        let transport = AsyncSmtpTransport::<Tokio1Executor>::relay(&self.host)
            .unwrap()
            .credentials(Credentials::from((&self.username, &self.password)))
            .build();

        // send the email
        transport.send(message).await
    }
}
