import { Server, Plugin } from "@hapi/hapi";
import * as HapiAuthJwt from "hapi-auth-jwt2";
import verifyJWT, { Validator } from "./verifyJWT";
import * as keystoresFromFile from "./keystores.json";
import { assert } from "@hapi/hoek";
import makeIssueTokenRoute from "./make-issue-token-route";

export type ClientSecrets = {
  [key: string]: string;
};

type Key = {
  kty: string;
  kid: string;
  use: string;
  crv: string;
  [key: string]: string;
};

/**
 * A keystore is built using the node-jose library, most of the
 * time we will use our oidc service to generate this file.
 */
type Keystore = { keys: Key[] };

type StrategyConfiguration = {
  name: string;
  validate?: Validator;
};
type StrategyConfigurationCollection = Array<StrategyConfiguration>;

type HapiOidcOptions = {
  tokenEndpoint?: string;
  clients?: ClientSecrets;
  fetchKeystore?: () => Keystore | Promise<Keystore>;
  validate?: Validator;
  dev?: boolean;
  omitCheckExp?: boolean;
  strategy?: StrategyConfiguration | StrategyConfigurationCollection;
};

const logger = (server: Server) => (
  tags: string | Array<string>,
  message?: Record<string, unknown> | string,
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

function isStrategyConfigurationCollection(
  strategy: StrategyConfiguration | StrategyConfigurationCollection
): strategy is StrategyConfigurationCollection {
  return !!(strategy as StrategyConfigurationCollection).length;
}

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

    if (options.strategy) {
      if (isStrategyConfigurationCollection(options.strategy)) {
        options.strategy.forEach((strategy) =>
          server.auth.strategy(strategy.name, "jwt", {
            verify: verifyJWT(
              logger(server),
              keystores,
              strategy.validate,
              options.omitCheckExp
            ),
          })
        );
      } else {
        server.auth.strategy(options.strategy.name, "jwt", {
          verify: verifyJWT(
            logger(server),
            keystores,
            options.strategy.validate,
            options.omitCheckExp
          ),
        });
      }
    } else {
      server.auth.strategy("oidc", "jwt", {
        verify: verifyJWT(
          logger(server),
          keystores,
          options.validate,
          options.omitCheckExp
        ),
      });
    }

    if (options.tokenEndpoint && options.clients) {
      server.route(makeIssueTokenRoute(options.clients, options.tokenEndpoint));
    }
  },
};

export default HapiOidc;
