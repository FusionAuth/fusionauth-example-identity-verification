import express, {type Application} from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import {FusionAuthSDK} from './sdk.ts';
// Add environment variables
import * as dotenv from "dotenv";
dotenv.config();

// ESM workaround for __dirname
const __filename: string = fileURLToPath(import.meta.url);
const __dirname: string = dirname(__filename);
const port: number = 8080; // default port to listen

if (!process.env.clientId) {
  console.error('Missing clientId from .env');
  process.exit();
}
if (!process.env.clientSecret) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
if (!process.env.baseURL) {
  console.error('Missing baseURL from .env');
  process.exit();
}

const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const baseURL = process.env.baseURL;

const sdk: FusionAuthSDK = new FusionAuthSDK(
    {
      apiKey: 'noapikeyneeded',
      applicationId: clientId,
      baseURL: baseURL,
      clientId: clientId,
      clientSecret: clientSecret,
      port: port
    }
);

const app: Application = express();

app.use(cookieParser());
app.use(express.urlencoded());

// Static Files
app.use('/static', express.static(path.join(__dirname, '../static/')));

// Homepage (always display this)
app.get("/", async (_req, res) => {
  res.sendFile(path.join(__dirname, '../templates/home.html'));
});

// Login route
// tag::login
app.get('/login', async (req, res) => {
  if (await sdk.userLoggedIn(req, res)) {
    res.redirect(302, '/account');
    return;
  }

  sdk.sendToLoginPage(res);
});
// end::login

// tag::register
app.get('/register', async (req, res) => {
  if (await sdk.userLoggedIn(req, res)) {
    res.redirect(302, '/account');
    return;
  }

  sdk.sendToRegistrationPage(res);
});
// end::register

// OAuth return route
app.get('/oauth-redirect', async (req, res) => {
  console.log("in oauthredirect");
  const accessToken = await sdk.handleOAuthRedirect(req);
  if (!accessToken) {
    console.error('Failed to get Access Token');
    res.redirect(302, '/');
    return;
  }

  sdk.logInUser(accessToken, res);
  res.redirect(302, '/account');
});

// Account page
// tag::account
app.get("/account", async (req, res) => {
  if (!await sdk.userHasAccess(req, res, ["admin", "user"])) {
    console.log("User does not have the correct role");
    res.redirect(302, '/login');
    return;
  }

  res.sendFile(path.join(__dirname, '../templates/account.html'));
});
// end::account

// Make change page
app.get("/make-change", async (req, res) => {
  if (!await sdk.userHasAccess(req, res, ["admin", "user"])) {
    res.redirect(302, '/login');
    return;
  }

  res.sendFile(path.join(__dirname, '../templates/make-change.html'));
});

// Make change submit
app.post("/make-change", async (req, res) => {
  if (!await sdk.userHasAccess(req, res, ["admin", "user"])) {
    res.status(403).json(JSON.stringify({
      error: 'Unauthorized'
    }))
    return;
  }

  const coins = {
    quarters: 0.25,
    dimes: 0.1,
    nickels: 0.05,
    pennies: 0.01,
  };

  let error = '';
  let message = '';
  try {
    message = 'We can make change for';
    let remainingAmount = +req.body.amount;
    for (const [name, nominal] of Object.entries(coins)) {
      let count = Math.floor(remainingAmount / nominal);
      remainingAmount = Math.round((remainingAmount - count * nominal) * 100) / 100;
      message = `${message} ${count} ${name}`;
    }
  } catch (ex: any) {
    error = `There was a problem converting the amount submitted. ${ex.message}`;
  }

  res.json(JSON.stringify({
    error,
    message
  }));
});

// Admin page
// tag::admin
app.get("/admin", async (req, res) => {
  if (!await sdk.userHasAccess(req, res, ["admin"])) {
    res.redirect(302, '/account');
    return;
  }

  res.sendFile(path.join(__dirname, '../templates/admin.html'));
});
// end::admin

// Logout redirect to FusionAuth
// tag::logout
app.get('/logout', (_req, res) => {
  sdk.sendToLogoutPage(res);
});
// end::logout

// OAuth logout return
// tag::oauth2-logout
app.get('/oauth2/logout', (_req, res) => {
  sdk.handleOAuthLogoutRedirect(res);
  res.redirect(302, '/')
});
// end::oauth2-logout

// Start the Express server
app.listen(port, () => {
  console.log(`server started at http://localhost:${port}`);
});
