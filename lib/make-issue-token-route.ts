import {
  ResponseToolkit,
  Request,
  ResponseObject,
  ServerRoute,
} from "@hapi/hapi";
import { Boom, Payload, Output } from "@hapi/boom";
import querystring from "querystring";
import Wreck from "@hapi/wreck";
import btoa from "btoa";
import { ClientSecrets, TokenPayload } from ".";

type OidcErrorData = { payload: Buffer };
type OidcError = Required<Boom<OidcErrorData>> & { output: OidcErrorOutput };
type OidcErrorPayload = Payload & { oidc_error: Record<string, unknown> };
type OidcErrorOutput = Output & { payload: OidcErrorPayload };

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type HapiResponse = ResponseObject | Boom<any>;
function isOidcError(response: HapiResponse): response is OidcError {
  return (response as OidcError).isBoom !== undefined;
}

const token = (clients: ClientSecrets, tokenEndpoint: string) => async (
  payload: TokenPayload
) => {
  const { client_id, ...tokenPayload } = payload;

  const options = {
    headers: {
      Authorization: "Basic " + btoa(`${client_id}:${clients[client_id]}`),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    payload: querystring.stringify(
      tokenPayload as querystring.ParsedUrlQueryInput
    ),
  };

  return await Wreck.post(tokenEndpoint, options);
};

const makeIssueTokenRoute = (
  clients: ClientSecrets,
  tokenEndpoint: string
): ServerRoute => {
  const issueToken = token(clients, tokenEndpoint);
  return {
    path: "/token",
    method: "POST",
    handler: async (request: Request) => {
      request.response;
      const { payload } = await issueToken(request.payload as TokenPayload);
      return payload;
    },
    options: {
      ext: {
        onPreResponse: {
          method: (request: Request, h: ResponseToolkit) => {
            const { response } = request;
            if (isOidcError(response)) {
              response.output.payload.oidc_error = JSON.parse(
                response.data.payload.toString()
              ) as Record<string, unknown>;
            }
            return h.continue;
          },
        },
      },
    },
  };
};

export default makeIssueTokenRoute;
