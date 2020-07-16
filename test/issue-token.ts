import * as Lab from "@hapi/lab";
import { expect } from "@hapi/code";
import nock from "nock";

const lab = Lab.script();
const { describe, it } = lab;
export { lab };

import { createInitializedServer } from "./util/server";
import plugin from "../lib";

type ScopeGeneratorOptions = { tokenEndpoint: string };
const passwordGrantNockScope = ({ tokenEndpoint }: ScopeGeneratorOptions) => {
  const tokenEndpointUrl = new URL(tokenEndpoint);
  return nock(tokenEndpointUrl.origin)
    .post(tokenEndpointUrl.pathname)
    .reply(204, {
      access_token: "ACCESS TOKEN",
      expires_in: 3600,
      token_type: "Bearer",
      id_token: "ID TOKEN",
      refresh_token: "REFRESH TOKEN",
    });
};

const badPasswordGrantNockScope = ({
  tokenEndpoint,
}: ScopeGeneratorOptions) => {
  const tokenEndpointUrl = new URL(tokenEndpoint);
  return nock(tokenEndpointUrl.origin)
    .post(tokenEndpointUrl.pathname)
    .reply(400, function () {
      // @ts-ignore bad types in nock
      this.req.response.statusMessage = "Bad Request";
      return {
        error: "invalid_grant",
        error_description: "invalid credentials provided",
      };
    });
};

const badGrantNockScope = ({ tokenEndpoint }: ScopeGeneratorOptions) => {
  const tokenEndpointUrl = new URL(tokenEndpoint);
  return nock(tokenEndpointUrl.origin)
    .post(tokenEndpointUrl.pathname)
    .reply(400, function () {
      // @ts-ignore bad types in nock
      this.req.response.statusMessage = "Bad Request";
      return {
        error: "unsupported_grant_type",
        error_description: "unsupported grant_type requested (FAKE GRANT)",
      };
    });
};

describe("Routes ::", () => {
  describe("issue token ::", () => {
    it("Proxies the token request to the token endpoint", async () => {
      const scope = passwordGrantNockScope({
        tokenEndpoint: "https://accounts.synapse.codes/op/token",
      });
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          tokenEndpoint: "https://accounts.synapse.codes/op/token",
          clients: { client_id: "ASECRET" },
        },
      });
      await server.inject({
        method: "POST",
        url: "/token",
        payload: {
          client_id: "client_id",
          grant_type: "password",
          password: "fake password",
          username: "fake-user",
        },
      });
      await server.stop();

      expect(scope.isDone()).to.equal(true);
    });

    it("does not register the token endpoint when the url is not configured", async () => {
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          clients: { client_id: "ASECRET" },
        },
      });
      const response = await server.inject({
        method: "POST",
        url: "/token",
        payload: {
          client_id: "client_id",
          grant_type: "password",
          password: "fake password",
          username: "fake-user",
        },
      });
      await server.stop();

      expect(response.statusCode).to.equal(404);
    });

    it("does not register the token endpoint when clients are not configured", async () => {
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          tokenEndpoint: "https://accounts.synapse.codes/op/token",
        },
      });
      const response = await server.inject({
        method: "POST",
        url: "/token",
        payload: {
          client_id: "client_id",
          grant_type: "password",
          password: "fake password",
          username: "fake-user",
        },
      });
      await server.stop();

      expect(response.statusCode).to.equal(404);
    });

    it("responds with well formatted errors when password is wrong", async () => {
      const scope = badPasswordGrantNockScope({
        tokenEndpoint: "https://accounts.synapse.codes/op/token",
      });
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          tokenEndpoint: "https://accounts.synapse.codes/op/token",
          clients: { client_id: "ASECRET" },
        },
      });
      const response = await server.inject({
        method: "POST",
        url: "/token",
        payload: {
          client_id: "client_id",
          grant_type: "password",
          password: "synapse2",
          username: "qa+admin@syn0.com",
        },
      });
      await server.stop();

      expect(scope.isDone()).to.equal(true);
      expect(JSON.parse(response.payload)).to.equal({
        statusCode: 400,
        error: "Bad Request",
        message: "Response Error: 400 Bad Request",
        oidc_error: {
          error: "invalid_grant",
          error_description: "invalid credentials provided",
        },
      });
    });

    it("responds with well formatted errors when grant is unsupported", async () => {
      const scope = badGrantNockScope({
        tokenEndpoint: "https://accounts.synapse.codes/op/token",
      });
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          tokenEndpoint: "https://accounts.synapse.codes/op/token",
          clients: { client_id: "ASECRET" },
        },
      });
      const response = await server.inject({
        method: "POST",
        url: "/token",
        payload: {
          client_id: "client_id",
          grant_type: "FAKE GRANT",
          fake: "stuff",
        },
      });
      await server.stop();

      expect(scope.isDone()).to.equal(true);
      expect(JSON.parse(response.payload)).to.equal({
        statusCode: 400,
        error: "Bad Request",
        message: "Response Error: 400 Bad Request",
        oidc_error: {
          error: "unsupported_grant_type",
          error_description: "unsupported grant_type requested (FAKE GRANT)",
        },
      });
    });
  });
});
