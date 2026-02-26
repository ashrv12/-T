import { c as createServerRpc } from "./createServerRpc-29xaFZcb.mjs";
import { i as isAuthConfigured, g as getRawAuthFromContext, r as refreshSession } from "./auth-helpers-CNd1dCOr.mjs";
import { c as createServerFn } from "./index.mjs";
import "./authkit-loader-BpUdXche.mjs";
import "../_chunks/_libs/@workos/authkit-session.mjs";
import "../_chunks/_libs/@workos-inc/node.mjs";
import "../_libs/iron-webcrypto.mjs";
import "../_libs/uint8array-extras.mjs";
import "../_libs/jose.mjs";
import "../_chunks/_libs/@tanstack/history.mjs";
import "../_chunks/_libs/@tanstack/router-core.mjs";
import "../_libs/cookie-es.mjs";
import "../_libs/tiny-invariant.mjs";
import "../_libs/seroval.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "node:stream";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "../_chunks/_libs/react.mjs";
import "../_chunks/_libs/@tanstack/react-router.mjs";
import "../_libs/react-dom.mjs";
import "../_libs/isbot.mjs";
import "../_libs/tiny-warning.mjs";
function sanitizeAuthForClient(auth) {
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
    impersonator: auth.impersonator
  };
}
const checkSessionAction_createServerFn_handler = createServerRpc({
  id: "2b41a5c96d491a63c28a578de3d4d24051e0c49a1bc852f533ba69a2b2cfe87a",
  name: "checkSessionAction",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/actions.js"
}, (opts) => checkSessionAction.__executeServer(opts));
const checkSessionAction = createServerFn({
  method: "GET"
}).handler(checkSessionAction_createServerFn_handler, () => {
  if (!isAuthConfigured()) {
    return false;
  }
  try {
    const auth = getRawAuthFromContext();
    return auth.user !== null;
  } catch {
    return false;
  }
});
const getAuthAction_createServerFn_handler = createServerRpc({
  id: "d680fad6bf472594a3d281e01817e508c37ec861e404bdf650536bc1adbf3ec0",
  name: "getAuthAction",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/actions.js"
}, (opts) => getAuthAction.__executeServer(opts));
const getAuthAction = createServerFn({
  method: "GET"
}).handler(getAuthAction_createServerFn_handler, () => {
  const auth = getRawAuthFromContext();
  return sanitizeAuthForClient(auth);
});
const refreshAuthAction_createServerFn_handler = createServerRpc({
  id: "947e9dcf13e76afdfcbe0776ab0d5d6a3d53be4cc38a7a6e46126b8a834dc98e",
  name: "refreshAuthAction",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/actions.js"
}, (opts) => refreshAuthAction.__executeServer(opts));
const refreshAuthAction = createServerFn({
  method: "POST"
}).inputValidator((options) => options).handler(refreshAuthAction_createServerFn_handler, async ({
  data: options
}) => {
  const result = await refreshSession(options?.organizationId);
  if (!result || !result.user) {
    return {
      user: null
    };
  }
  return sanitizeAuthForClient(result);
});
const getAccessTokenAction_createServerFn_handler = createServerRpc({
  id: "8fbde53c147d0c40a3353d3a302be03bbd2d78a0555fefaa7273d58c45c684c9",
  name: "getAccessTokenAction",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/actions.js"
}, (opts) => getAccessTokenAction.__executeServer(opts));
const getAccessTokenAction = createServerFn({
  method: "GET"
}).handler(getAccessTokenAction_createServerFn_handler, () => {
  if (!isAuthConfigured()) {
    return void 0;
  }
  try {
    const auth = getRawAuthFromContext();
    return auth.user ? auth.accessToken : void 0;
  } catch {
    return void 0;
  }
});
const refreshAccessTokenAction_createServerFn_handler = createServerRpc({
  id: "760f6ac025a9178fc087c5cfdaf3a82001e24863e076a45526349c20046ddb5f",
  name: "refreshAccessTokenAction",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/actions.js"
}, (opts) => refreshAccessTokenAction.__executeServer(opts));
const refreshAccessTokenAction = createServerFn({
  method: "POST"
}).handler(refreshAccessTokenAction_createServerFn_handler, async () => {
  const result = await refreshSession();
  return result?.user ? result.accessToken : void 0;
});
const switchToOrganizationAction_createServerFn_handler = createServerRpc({
  id: "4f82c552b3fb8ae95fe0344bc1ecb36769a06605fd5dd557a2bd32973b3b48e2",
  name: "switchToOrganizationAction",
  filename: "node_modules/@workos/authkit-tanstack-react-start/dist/server/actions.js"
}, (opts) => switchToOrganizationAction.__executeServer(opts));
const switchToOrganizationAction = createServerFn({
  method: "POST"
}).inputValidator((data) => data).handler(switchToOrganizationAction_createServerFn_handler, async ({
  data
}) => {
  const result = await refreshSession(data.organizationId);
  if (!result || !result.user) {
    return {
      user: null
    };
  }
  return sanitizeAuthForClient(result);
});
export {
  checkSessionAction_createServerFn_handler,
  getAccessTokenAction_createServerFn_handler,
  getAuthAction_createServerFn_handler,
  refreshAccessTokenAction_createServerFn_handler,
  refreshAuthAction_createServerFn_handler,
  switchToOrganizationAction_createServerFn_handler
};
