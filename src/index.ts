import express from "express"
import cookieParser from 'cookie-parser'
import { Auth, AuthConfig, skipCSRFCheck } from "@auth/core"
import { Request, Response, NextFunction } from 'express'
import { decode } from "@auth/core/jwt"
import { login, mastodon } from "masto"

declare module "express" {
    interface Request {
        accessToken?: string
        mastoClient?: mastodon.Client,
        profile?: mastodon.v1.Account
    }
}

async function getMastodonConfig(serverBaseUrl: string, callbackBaseUrl: string): Promise<AuthConfig> {

    const serverCredentials = await fetch(serverBaseUrl + "/api/v1/apps", {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            "client_name": "authjsplaying",
            "redirect_uris": callbackBaseUrl + "/api/auth/callback/mastodon"
        })
    });
    const data = await serverCredentials.json();

    const config: AuthConfig = {
        providers: [{
            id: "mastodon",
            name: "Mastodon",
            type: "oauth",
            authorization: {
                url: serverBaseUrl + "/oauth/authorize",
                params: {
                    'response_type': 'code',
                    'redirect_uri': callbackBaseUrl + "/api/auth/callback/mastodon",
                    'scope': 'read'
                }
            },
            token: serverBaseUrl + "/oauth/token",
            clientId: data.client_id,
            clientSecret: data.client_secret,
            userinfo: serverBaseUrl + "/api/v1/accounts/verify_credentials",
            profile: (data: any) => {
                return {
                    id: data.id,
                }
            }
        }],
        callbacks: {
            async jwt({ token, user, account, profile, isNewUser }) {
                token.access_token = account?.access_token
                token.profile = profile
                return token
            }
        },
        skipCSRFCheck: skipCSRFCheck,
        trustHost: true,
        secret: "secret",
    };

    return config;
}

const app = express();
const port = 3000;
const baseUrl = "http://localhost:" + port;
const mastodonBaseUrl = "https://mastodon.social";
const config = await getMastodonConfig(mastodonBaseUrl, baseUrl);
const router = express.Router();

app.use(cookieParser());

app.all('/api/auth/*', async (req: Request, res: Response) => {

    const headers = new Headers();

    for (const headerName in req.headers) {
        const headerValue: string = req.headers[headerName]?.toString() ?? "";
        if (Array.isArray(headerValue)) {
            for (const value of headerValue) {
                headers.append(headerName, value);
            }
        } else {
            headers.append(headerName, headerValue);
        }
    }

    const request = new Request(baseUrl + req.url, {
        method: req.method,
        headers: headers,
        body: req.body
    });

    const response = await Auth(request, config);
    
    res.status(response.status);
    res.contentType(response.headers.get("content-type") ?? "text/plain");
    response.headers.forEach((value, key) => {
        if (value) {
            res.setHeader(key, value);
        }
    });
    const body = await response.text();
    
    res.send(body);
});

async function authentication(req: Request, res: Response, next: NextFunction) {
    const token = req.cookies['next-auth.session-token'] || null

    if (token == null) {
        return res.redirect("/api/auth/signin")
    }

    const decoded = await decode({
        token: token,
        secret: "secret",
    });

    if (decoded !== null) {
        req.accessToken = decoded.access_token as string;

        try {
            const masto = await login({
                url: mastodonBaseUrl,
                accessToken: req.accessToken
            })

            req.mastoClient = masto
            req.profile = await req.mastoClient.v1.accounts.verifyCredentials()

        } catch (error) {
            res.clearCookie('next-auth.session-token')
            res.clearCookie('next-auth.csrf-token')
            res.clearCookie('next-auth.callback-url')
            res.clearCookie('next-auth.pkce.code_verifier')
            
            return res.redirect("/api/auth/signin")
        }
    }

    next()
}

router.use(authentication)

router.get("/", async (req: Request, res: Response) => {

    res.set('Content-Type', 'text/html');

    res.write("Hello " + req.profile?.username + "\n")

    const publicTimeline = await req.mastoClient?.v1.timelines.listHome({ limit: 10 })
    publicTimeline?.forEach((status: { content: string }) => {
        res.write(status.content + "\n")
    })

    res.write("<a href='/api/auth/signout'>Sign out</a>")

    res.send()
});

app.use(router)

app.listen(3000)