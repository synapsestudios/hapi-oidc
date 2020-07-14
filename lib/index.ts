import { Server, Plugin } from "@hapi/hapi";
import * as HapiAuthJwt from "hapi-auth-jwt2";
import verifyJWT, { Validator } from "./verifyJWT";
import * as keystoresFromFile from "./keystores.json";
import { assert } from "@hapi/hoek";
import makeIssueTokenRoute from "./make-issue-token-route";

export type ClientSecrets = {
  [key: string]: string;
};

type HapiOidcOptions = {
  tokenEndpoint?: string;
  clients?: ClientSecrets;
  fetchKeystore?: () => object | Promise<object>;
  validate?: Validator;
  dev?: boolean;
  omitCheckExp?: boolean;
};

const logger = (server: Server) => (
  tags: string | Array<string>,
  message?: object | string,
  timestamp?: number
) => server.log(tags, message, timestamp);

type AuthorizationGrantTokenPayload = {
  readonly client_id: string;
};

type PasswordGrantTokenPayload = {
  readonly client_id: string;
  readonly username: string;
  readonly password: string;
  readonly grant_type: "password";
};

export type TokenPayload =
  | AuthorizationGrantTokenPayload
  | PasswordGrantTokenPayload;

const HapiOidc: Plugin<HapiOidcOptions> = {
  name: "hapi-oidc",
  register: async (server, options) => {
    assert(
      options.fetchKeystore || options.dev,
      "hapi-oidc: fetchKeystore required when not operating in dev mode"
    );

    const keystores = options.fetchKeystore
      ? await options.fetchKeystore()
      : keystoresFromFile;

    await server.register(HapiAuthJwt, { once: true });
    server.auth.strategy("oidc", "jwt", {
      verify: verifyJWT(
        logger(server),
        keystores,
        options.validate,
        options.omitCheckExp
      ),
    });

    if (options.tokenEndpoint && options.clients) {
      server.route(makeIssueTokenRoute(options.clients, options.tokenEndpoint));
    }
  },
};

export default HapiOidc;
