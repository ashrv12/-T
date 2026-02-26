import { c as createServerRpc } from "./createServerRpc-29xaFZcb.mjs";
import { g as getAuth } from "./server-functions-D20kG-HZ.mjs";
import { c as createServerFn } from "./index.mjs";
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
const fetchWorkosAuth_createServerFn_handler = createServerRpc({
  id: "0360bf05551679460fd95ca0926c27cce907fb3a5c6fea18e38ca35ca1d323a7",
  name: "fetchWorkosAuth",
  filename: "src/routes/__root.tsx"
}, (opts) => fetchWorkosAuth.__executeServer(opts));
const fetchWorkosAuth = createServerFn({
  method: "GET"
}).handler(fetchWorkosAuth_createServerFn_handler, async () => {
  const auth = await getAuth();
  const {
    user
  } = auth;
  return {
    userId: user?.id ?? null,
    token: user ? auth.accessToken : null
  };
});
export {
  fetchWorkosAuth_createServerFn_handler
};
