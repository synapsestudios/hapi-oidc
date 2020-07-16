import * as Lab from "@hapi/lab";
import { expect } from "@hapi/code";
import { stub } from "sinon";
import { Server } from "@hapi/hapi";

import keystores from "./util/keystores.json";
import { createInitializedServer } from "./util/server";
import getTokenWithoutKs from "./util/getToken";
import plugin from "../lib";

const lab = Lab.script();
const { describe, it } = lab;
export { lab };

const getToken = getTokenWithoutKs();

const addAuthCheckRoute = (server: Server) =>
  server.route({
    method: "GET",
    path: "/auth-check",
    handler: () => ({ message: "success" }),
    options: { auth: "oidc" },
  });

describe("Integration", () => {
  describe("oidc strategy", () => {
    it("Can be used in a route", async () => {
      const server = await createInitializedServer();
      await server.register({ plugin, options: { dev: true } });
      addAuthCheckRoute(server);

      const token = await getToken();
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(200);
      expect(response.result).to.equal({ message: "success" });
    });

    it("Uses keystore override function", async () => {
      const server = await createInitializedServer();
      const fetchKeystoreSpy = stub().returns(Promise.resolve(keystores));
      await server.register({
        plugin,
        options: {
          fetchKeystore: fetchKeystoreSpy,
        },
      });

      addAuthCheckRoute(server);

      const token = await getTokenWithoutKs(keystores)();
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(200);
      expect(response.result).to.equal({ message: "success" });
      expect(fetchKeystoreSpy.calledOnce).to.equal(true);
    });

    it("Fails to register if no keystore overrided is provided unless env is set to development", async () => {
      const server = await createInitializedServer();
      const rejects = () =>
        server.register({
          plugin,
          options: {},
        });
      await expect(rejects()).to.reject();
      await server.stop();
    });

    it("Returns a 401 when no authorization header is provided", async () => {
      const server = await createInitializedServer();
      await server.register({ plugin, options: { dev: true } });
      addAuthCheckRoute(server);

      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
      });

      await server.stop();

      expect(response.statusCode).to.equal(401);
    });

    it("Returns a 200 when the token contains an expiration date", async () => {
      const server = await createInitializedServer();
      await server.register({ plugin, options: { dev: true } });
      addAuthCheckRoute(server);

      const token = await getToken({ exp: Date.now() + 10000 });
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(200);
      expect(response.result).to.equal({ message: "success" });
    });

    it("Returns a 200 when token is expired but omitCheckExp is true", async () => {
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: { dev: true, omitCheckExp: true },
      });
      addAuthCheckRoute(server);

      const token = await getToken({ exp: Date.now() - 10000 });
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(200);
      expect(response.result).to.equal({ message: "success" });
    });

    it("Returns a 401 when token is expired", async () => {
      const server = await createInitializedServer();
      await server.register({ plugin, options: { dev: true } });
      addAuthCheckRoute(server);

      const token = await getToken({ exp: Date.now() - 10000 });
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(401);
    });

    it("Returns a 401 when token is invalid", async () => {
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
        },
      });

      addAuthCheckRoute(server);

      // Get a token signed with an inompatible key
      const token = await getTokenWithoutKs(keystores)();
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(401);
    });

    it("Returns a 401 when custom validate function returns isValid as false", async () => {
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          validate: () => ({ isValid: false }),
        },
      });
      addAuthCheckRoute(server);

      const token = await getToken();
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(401);
    });

    it("Returns a 500 when the custom validator throws an error", async () => {
      const server = await createInitializedServer();
      await server.register({
        plugin,
        options: {
          dev: true,
          validate: () => {
            throw new Error("fake error");
          },
        },
      });
      addAuthCheckRoute(server);

      const token = await getToken();
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(500);
    });

    it("Returns a 500 when the custom validator returns an unexpected type", async () => {
      const server = await createInitializedServer();
      await server.register({
        // @ts-ignore: i'm passing the wrong type on purpose
        plugin,
        options: {
          dev: true,
          validate: () => true,
        },
      });
      addAuthCheckRoute(server);

      const token = await getToken();
      const response = await server.inject({
        method: "GET",
        url: "/auth-check",
        headers: { Authorization: `Bearer ${token} ` },
      });

      await server.stop();

      expect(response.statusCode).to.equal(500);
    });
  });
});
