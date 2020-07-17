import atob from "atob";
import jose from "node-jose";
import isPast from "date-fns/isPast";
import { assert, contain } from "@hapi/hoek";

type RequestWithToken = Request & {
  auth: {
    /**
     * Base64 encoded JWT. This property on request.auth is provided
     * by the hapi-jwt2 plugin
     */
    token: string;
  };
};

/**
 * Registered Claims: https://tools.ietf.org/html/rfc7519#section-4.1
 *
 * "These are a set of predefined claims which are not mandatory but recommended,
 * to provide a set of useful, interoperable claims."
 */
export type DecodedJWTPayload = {
  /**
   * Who issued this jWT?
   */
  iss?: string;
  /**
   * Who is the subject (user) of this JWT?
   */
  sub?: string;
  /**
   * When does this JWT expire?
   */
  exp?: number;
  /**
   * "not before" identifies the time before which the JWT MUST NOT be accepted for processing
   */
  nbf?: number; //
  /**
   * when was this JWT issued at
   */
  iat?: string;
  /**
   * unique identifier for the JWT
   */
  jti?: string;
};

export type DecodedJWTHeader = {
  typ: string;
  alg: string;
  kid: string;
};

type ValidationObject = {
  isValid: boolean;
  credentials: unknown;
};
export type ValidationResult = ValidationObject | Promise<ValidationObject>;
export type Validator = (d: DecodedJWTPayload) => ValidationResult;

type Log = (
  tags: string | Array<string>,
  message?: Record<string, unknown> | string,
  timestamp?: number
) => void;

const defaultValidate: Validator = (decoded) => ({
  isValid: true,
  credentials: decoded,
});

const checkValidationResultType = (returnValue: ValidationResult) => {
  assert(
    typeof returnValue === "object",
    "hapi-oidc: custom validator must return an object"
  );
  assert(
    contain(returnValue, "isValid"),
    "hapi-oidc: custom validator must return an object with an isValid property"
  );
  return returnValue;
};

// copied type from the node-jose package
type SerializedKeystore = Record<string, unknown> | string;

const verify = (
  log: Log,
  keystoreSerialized: SerializedKeystore,
  validate = defaultValidate,
  omitCheckExp = false
) => async (decoded: DecodedJWTPayload, request: RequestWithToken) => {
  const keystore = await jose.JWK.asKeyStore(keystoreSerialized);
  const token = request.auth.token;
  const header = JSON.parse(atob(token.split(".")[0])) as DecodedJWTHeader;

  const key = keystore.get(header.kid);

  try {
    // this line throws if the key isn't valid
    await jose.JWS.createVerify(key).verify(token);
  } catch (e) {
    log(["error", "synapse-oidc"], e);
    return { isValid: false };
  }

  if (decoded.exp && !omitCheckExp) {
    if (isPast(decoded.exp)) {
      return { isValid: false };
    }
  }

  return checkValidationResultType(validate(decoded));
};

export default verify;
