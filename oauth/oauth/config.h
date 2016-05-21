/*
 * The MIT License
 *
 * Copyright (c) 2014 Institute of Computer Science, Masaryk University.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#ifndef CONFIG_H
#define CONFIG_H

/************************************************
 *
 *              CONFIG FILE
 *
 * *********************************************/

// The template must be observed, example - client_id = "client_id=...informations...";

// Required informations:
const char* client_id = "client_id=157665463979-a7m5opdjnqfkdvcr7isppbn69afk6acq.apps.googleusercontent.com";
const char* client_secret = "client_secret=4Te40AOGwc8PUUOGMlIjx8jA";


// Required informations for authorization code grant
#define redirect "redirect_uri=http://127.0.0.1"
#define port_num "6501"


// Optional informations:
#define scopes "scope=profile"
#define login "login_hint=prikryl.ond@gmail.com"
// state is given in main


// Endpoints:
const char* google_auth_endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
const char* google_token_endpoint = "https://www.googleapis.com/oauth2/v4/token";
const char* google_data_endpoint = "https://www.googleapis.com/userinfo/v2/me";

#endif // CONFIG_H
