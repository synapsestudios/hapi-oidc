import { ResponseToolkit, Request } from "@hapi/hapi";
import querystring from "querystring";
import Wreck from "@hapi/wreck";
import btoa from "btoa";
import { ClientSecrets, TokenPayload } from ".";

type RequestWithPossibleErrorResponse = Request & {
  response: {
    isBoom?: boolean;
    data?: object;
    output?: {
      payload?: { [key: string]: any };
    };
  };
};

const token = (clients: ClientSecrets, tokenEndpoint: string) => async (
  payload: TokenPayload
) => {
  const { client_id, ...tokenPayload } = payload;

  const options = {
    headers: {
      Authorization: "Basic " + btoa(`${client_id}:${clients[client_id]}`),
      "Content-Type": "application/x-www-form-urlencoded",
    },
    //@ts-ignore weird types for querystring
    payload: querystring.stringify(tokenPayload),
  };

  return await Wreck.post(tokenEndpoint, options);
};

const makeIssueTokenRoute = (clients: ClientSecrets, tokenEndpoint: string) => {
  const issueToken = token(clients, tokenEndpoint);
  return {
    path: "/token",
    method: "POST",
    handler: async (request: Request) => {
      const { payload } = await issueToken(request.payload as TokenPayload);
      return payload;
    },
    options: {
      ext: {
        onPreResponse: {
          method: (
            request: RequestWithPossibleErrorResponse,
            h: ResponseToolkit
          ) => {
            const {
              response: { isBoom, data, output },
            } = request;
            if (isBoom && data && output && output.payload) {
              output.payload.oidc_error = JSON.parse(
                request.response.data.payload.toString()
              );
            }
            return h.continue;
          },
        },
      },
    },
  };
};

export default makeIssueTokenRoute;
