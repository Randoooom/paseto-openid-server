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
