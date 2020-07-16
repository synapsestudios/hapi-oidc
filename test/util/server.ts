import { server } from "@hapi/hapi";

export const createInitializedServer = async () => {
  const testServer = server({
    port: 3000,
    host: "localhost",
  });
  await testServer.initialize();
  return testServer;
};

process.on("unhandledRejection", (err) => {
  console.log(err);
  process.exit(1);
});
