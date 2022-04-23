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

CREATE TABLE IF NOT EXISTS clients
(
    sub                   uuid PRIMARY KEY      DEFAULT gen_random_uuid(),
    name                  varchar(255) NOT NULL,
    given_name            varchar(255) NOT NULL,
    family_name           varchar(255) NOT NULL,
    middle_name           varchar(255) NULL,
    nickname              varchar(255) NOT NULL UNIQUE,
    preferred_username    varchar(255) NOT NULL,
    profile               varchar(255) NOT NULL,
    picture               varchar(255) NOT NULL,
    website               varchar(255) NULL,
    email                 varchar(255) NOT NULL UNIQUE,
    email_verified        bool                  DEFAULT FALSE,
    gender                varchar(255) NOT NULL,
    birthdate             varchar(255) NOT NULL,
    zoneinfo              varchar(255) NOT NULL,
    locale                varchar(255) NOT NULL,
    phone_number          varchar(255) NULL UNIQUE,
    phone_number_verified bool                  DEFAULT FALSE,
    updated_at            timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS addresses
(
    uuid           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    formatted      varchar(255) NOT NULL,
    street_address varchar(255) NOT NULL,
    locality       varchar(255) NOT NULL,
    region         varchar(255) NOT NULL,
    postal_code    varchar(255) NOT NULL,
    country        varchar(255) NOT NULL,
    client         uuid         NOT NULL REFERENCES clients (sub)
);

CREATE TABLE IF NOT EXISTS client_authentication_data
(
    uuid       uuid PRIMARY KEY      DEFAULT gen_random_uuid(),
    password   varchar(255) NOT NULL,
    secret     varchar(255) NOT NULL,
    totp       bool                  DEFAULT FALSE,
    last_login timestamptz  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    client     uuid         NOT NULL REFERENCES clients (sub)
);

CREATE TABLE IF NOT EXISTS client_verification_tokens
(
    uuid   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    client uuid NOT NULL REFERENCES clients (sub)
);
