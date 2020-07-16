import jose from "node-jose";
import { DecodedJWTPayload } from "../../lib/verifyJWT";
import keystoreJson from "../../lib/keystores.json";

const btoa = (string: string) => {
  return Buffer.from(string).toString("base64").replace(/=+$/, "");
};

const getToken = (keystore = keystoreJson) => async (
  payloadData = {} as DecodedJWTPayload
) => {
  const payload = btoa(JSON.stringify(payloadData));

  const keystoreObject = await jose.JWK.asKeyStore(keystore);
  const key = await jose.JWK.asKey(keystoreObject.get("sig-rs-0"));
  const payloadBuffer = jose.util.base64url.decode(payload);

  const jwt = await jose.JWS.createSign(
    { format: "compact", fields: { typ: "JWT" } },
    key
  )
    .update(payloadBuffer)
    .final();

  return jwt;
};

export default getToken;
