# Synapse Studios hapi-oidc

This plugin shortcuts some of the integration with the [Synapse OIDC Service](https://github.com/synapsestudios/oidc-platform). It registers the [hapi-auth-jwt2](https://github.com/dwyl/hapi-auth-jwt2/issues) plugin on the server and configures authentication strategies to use in your routes.

This plugin owns token verification, but leaves app specific validation up to you. It will also optionally register a token endpoint which will proxy token requests (using your client secrets) to the OIDC Service.

# Usage
```
// Register the plugin
await server.register({ plugin: HapiOidc, options: { dev: true } });

server.route({
  method: "GET",
  path: "/auth-check",
  handler: () => ({ message: "success" }),

  // the oidc auth strategy is provided by this plugin
  options: { auth: "oidc" },
});
```

## Use Case: Two Different Validation Functions
If you have different validation needs per endpoint then you should configure multiple authentication strategies to accomodate those needs. A common use case for this might be that deactivated users shouldn't be able to use most of your endpoints, but you might allow them to access one or two specific routes in order to reactivate themselves.

```
// Register the plugin
await server.register({ plugin: HapiOidc, options: { strategy: [
  {
    name: 'oidc-active',
    validate: async (tokenPayload) => {
      const user = await fetchUser(tokenPayload.sub);
      return user?.active ? { isValid: true, credentials: tokenPayload } : { isValid : false };
    }
  }, {
    name: 'oidc-any',
    validate: async (tokenPayload) => {
      const user = await fetchUser(tokenPayload.sub);
      return user ? { isValid: true, credentials: tokenPayload } : { isValid: false };
    }
  }
]}});

// Use the strategies
server.route({
  method: "GET",
  path: "/user/me",
  handler: () => ({ message: 'success' });
  options: { auth: 'oidc-any' }            // any user can access their own user record
})
```

## Plugin Options
```
type HapiOidcOptions = {
  tokenEndpoint?: string;                                            // the OIDC service token endpoint. `https://oidc.app.com/op/token`
  clients?: ClientSecrets;                                           // map of client id/secret pairs. { 'client1' : 'secret1', 'client2' : 'secret2' }
  fetchKeystore?: () => Keystore | Promise<Keystore>;                // function that returns a keystore
  validate?: Validator;                                              // Function that validates the token and optionally appends values to the hapi auth object
  dev?: boolean;                                                     // If this flag is true then the plugin will load up a default keystore for dev/testing purposes
  omitCheckExp?: boolean;                                            // Set this to true if you don't want to check the token's expiration date
  strategy?: StrategyConfiguration | StrategyConfigurationCollection // Override the default 'oidc' strategy with your own strategy names
};
```
