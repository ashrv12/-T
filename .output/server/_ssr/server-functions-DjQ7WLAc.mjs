import { c as createServerRpc } from "./createServerRpc-29xaFZcb.mjs";
import { E as redirect } from "../_chunks/_libs/@tanstack/router-core.mjs";
import { g as getRawAuthFromContext, a as getRedirectUriFromContext, r as refreshSession } from "./auth-helpers-CNd1dCOr.mjs";
import { g as getAuthkit } from "./authkit-loader-BpUdXche.mjs";
import { c as createServerFn } from "./index.mjs";
import "../_libs/cookie-es.mjs";
import "../_chunks/_libs/@tanstack/history.mjs";
import "../_libs/tiny-invariant.mjs";
import "../_libs/seroval.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "node:stream";
import "../_chunks/_libs/@workos/authkit-session.mjs";
import "../_chunks/_libs/@workos-inc/node.mjs";
import "../_libs/iron-webcrypto.mjs";
import "../_libs/uint8array-extras.mjs";
import "../_libs/jose.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "../_chunks/_libs/react.mjs";
import "../_chunks/_libs/@tanstack/react-router.mjs";
import "../_libs/react-dom.mjs";
import "../_libs/isbot.mjs";
import "../_libs/tiny-warning.mjs";
const getSignOutUrl_createServerFn_handler = createServerRpc({
  id: "da5afb9bdc4a4c4273a3e985c6a21506be405bd882083153198c354906cc9671",
  name: "getSignOutUrl",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => getSignOutUrl.__executeServer(opts));
const getSignOutUrl = createServerFn({
  method: "POST"
}).inputValidator((options) => options).handler(getSignOutUrl_createServerFn_handler, async ({
  data
}) => {
  const auth = getAuthFromContext();
  if (!auth.user || !auth.sessionId) {
    return {
      url: null
    };
  }
  const authkit = await getAuthkit();
  const {
    logoutUrl
  } = await authkit.signOut(auth.sessionId, {
    returnTo: data?.returnTo
  });
  return {
    url: logoutUrl
  };
});
const signOut_createServerFn_handler = createServerRpc({
  id: "89c05eca9d1a26569b5729c9f53081a3d87100033ce9867c75c50046d7e4fd84",
  name: "signOut",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => signOut.__executeServer(opts));
const signOut = createServerFn({
  method: "POST"
}).inputValidator((options) => options).handler(signOut_createServerFn_handler, async ({
  data
}) => {
  const auth = getAuthFromContext();
  if (!auth.user || !auth.sessionId) {
    throw redirect({
      to: data?.returnTo || "/",
      throw: true,
      reloadDocument: true
    });
  }
  const authkit = await getAuthkit();
  const {
    logoutUrl,
    headers: headersBag
  } = await authkit.signOut(auth.sessionId, {
    returnTo: data?.returnTo
  });
  const headers = new Headers();
  if (headersBag) {
    for (const [key, value] of Object.entries(headersBag)) {
      if (Array.isArray(value)) {
        value.forEach((v) => headers.append(key, v));
      } else {
        headers.set(key, value);
      }
    }
  }
  throw redirect({
    href: logoutUrl,
    throw: true,
    reloadDocument: true,
    headers
  });
});
function getAuthFromContext() {
  const auth = getRawAuthFromContext();
  if (!auth.user) {
    return {
      user: null
    };
  }
  return {
    user: auth.user,
    sessionId: auth.sessionId,
    organizationId: auth.claims?.org_id,
    role: auth.claims?.role,
    roles: auth.claims?.roles,
    permissions: auth.claims?.permissions,
    entitlements: auth.claims?.entitlements,
    featureFlags: auth.claims?.feature_flags,
    impersonator: auth.impersonator,
    accessToken: auth.accessToken
  };
}
const getAuth_createServerFn_handler = createServerRpc({
  id: "e206de2e2ad20d09cf25c2bcf19972cbd4a9f45957227b050a63f26acbd0c3c0",
  name: "getAuth",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => getAuth.__executeServer(opts));
const getAuth = createServerFn({
  method: "GET"
}).handler(getAuth_createServerFn_handler, () => {
  return getAuthFromContext();
});
const getAuthorizationUrl_createServerFn_handler = createServerRpc({
  id: "23de6bed10ade3fd06436c64113f12c9c17b5732e4394a29dd4bb78628937c8c",
  name: "getAuthorizationUrl",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => getAuthorizationUrl.__executeServer(opts));
const getAuthorizationUrl = createServerFn({
  method: "GET"
}).inputValidator((options) => options).handler(getAuthorizationUrl_createServerFn_handler, async ({
  data: options = {}
}) => {
  const authkit = await getAuthkit();
  const contextRedirectUri = getRedirectUriFromContext();
  if (contextRedirectUri && !options.redirectUri) {
    return authkit.getAuthorizationUrl({
      ...options,
      redirectUri: contextRedirectUri
    });
  }
  return authkit.getAuthorizationUrl(options);
});
const getSignInUrl_createServerFn_handler = createServerRpc({
  id: "859354b50f88ba44a183938ef69b68472bfaeeb450c54e1b943f450acbb603d4",
  name: "getSignInUrl",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => getSignInUrl.__executeServer(opts));
const getSignInUrl = createServerFn({
  method: "GET"
}).inputValidator((data) => data).handler(getSignInUrl_createServerFn_handler, async ({
  data
}) => {
  const options = typeof data === "string" ? {
    returnPathname: data
  } : data;
  const contextRedirectUri = getRedirectUriFromContext();
  const authkit = await getAuthkit();
  if (contextRedirectUri && !options?.redirectUri) {
    return authkit.getSignInUrl({
      ...options,
      redirectUri: contextRedirectUri
    });
  }
  return authkit.getSignInUrl(options);
});
const getSignUpUrl_createServerFn_handler = createServerRpc({
  id: "6682d12152eb1079fb9ecabcc55f8a5871370cee230d6597b5ee1cca2e521289",
  name: "getSignUpUrl",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => getSignUpUrl.__executeServer(opts));
const getSignUpUrl = createServerFn({
  method: "GET"
}).inputValidator((data) => data).handler(getSignUpUrl_createServerFn_handler, async ({
  data
}) => {
  const options = typeof data === "string" ? {
    returnPathname: data
  } : data;
  const contextRedirectUri = getRedirectUriFromContext();
  const authkit = await getAuthkit();
  if (contextRedirectUri && !options?.redirectUri) {
    return authkit.getSignUpUrl({
      ...options,
      redirectUri: contextRedirectUri
    });
  }
  return authkit.getSignUpUrl(options);
});
const switchToOrganization_createServerFn_handler = createServerRpc({
  id: "c9b8e0dd9c7949a3bc8661897cf67ed60b574436f842b90d08ef1bf21a94eb17",
  name: "switchToOrganization",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/server-functions.js"
}, (opts) => switchToOrganization.__executeServer(opts));
const switchToOrganization = createServerFn({
  method: "POST"
}).inputValidator((data) => data).handler(switchToOrganization_createServerFn_handler, async ({
  data
}) => {
  const auth = getAuthFromContext();
  if (!auth.user) {
    throw redirect({
      to: data.returnTo || "/"
    });
  }
  const result = await refreshSession(data.organizationId);
  if (!result?.user) {
    throw redirect({
      to: data.returnTo || "/"
    });
  }
  return {
    user: result.user,
    sessionId: result.sessionId,
    organizationId: result.claims?.org_id,
    role: result.claims?.role,
    roles: result.claims?.roles,
    permissions: result.claims?.permissions,
    entitlements: result.claims?.entitlements,
    featureFlags: result.claims?.feature_flags,
    impersonator: result.impersonator,
    accessToken: result.accessToken
  };
});
export {
  getAuth_createServerFn_handler,
  getAuthorizationUrl_createServerFn_handler,
  getSignInUrl_createServerFn_handler,
  getSignOutUrl_createServerFn_handler,
  getSignUpUrl_createServerFn_handler,
  signOut_createServerFn_handler,
  switchToOrganization_createServerFn_handler
};
