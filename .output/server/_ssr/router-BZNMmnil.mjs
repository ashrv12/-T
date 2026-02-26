import { j as jsxRuntimeExports, r as reactExports } from "../_chunks/_libs/react.mjs";
import { E as redirect } from "../_chunks/_libs/@tanstack/router-core.mjs";
import { c as createRouter, u as useNavigate, a as createRootRouteWithContext, O as Outlet, b as createFileRoute, l as lazyRouteComponent, H as HeadContent, S as Scripts } from "../_chunks/_libs/@tanstack/react-router.mjs";
import { C as ConvexQueryClient } from "../_chunks/_libs/@convex-dev/react-query.mjs";
import { s as setupRouterSsrQueryIntegration } from "../_chunks/_libs/@tanstack/react-router-ssr-query.mjs";
import { a as getSignOutUrl, c as createSsrRpc, g as getAuth, b as getSignInUrl, d as getSignUpUrl } from "./server-functions-D20kG-HZ.mjs";
import { c as createServerFn } from "./index.mjs";
import { g as getAuthkit } from "./authkit-loader-BpUdXche.mjs";
import { d as decodeState } from "./auth-helpers-CNd1dCOr.mjs";
import { C as ConvexReactClient, b as ConvexProviderWithAuth } from "../_libs/convex.mjs";
import { b as QueryClient } from "../_chunks/_libs/@tanstack/query-core.mjs";
import "../_libs/cookie-es.mjs";
import "../_chunks/_libs/@tanstack/history.mjs";
import "../_libs/tiny-invariant.mjs";
import "../_libs/seroval.mjs";
import "../_libs/seroval-plugins.mjs";
import "node:stream/web";
import "node:stream";
import "../_libs/react-dom.mjs";
import "../_libs/isbot.mjs";
import "../_libs/tiny-warning.mjs";
import "../_chunks/_libs/@tanstack/react-query.mjs";
import "../_chunks/_libs/@tanstack/router-ssr-query-core.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "../_chunks/_libs/@workos/authkit-session.mjs";
import "../_chunks/_libs/@workos-inc/node.mjs";
import "../_libs/iron-webcrypto.mjs";
import "../_libs/uint8array-extras.mjs";
import "../_libs/jose.mjs";
function handleCallbackRoute(options = {}) {
  return async ({ request }) => {
    return handleCallbackInternal(request, options);
  };
}
async function handleCallbackInternal(request, options) {
  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code) {
    if (options.onError) {
      return options.onError({ error: new Error("Missing authorization code"), request });
    }
    return new Response(JSON.stringify({ error: { message: "Missing authorization code" } }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const { returnPathname: stateReturnPathname, customState } = decodeState(state);
    const returnPathname = options.returnPathname ?? stateReturnPathname;
    const response = new Response();
    const authkit = await getAuthkit();
    const result = await authkit.handleCallback(request, response, { code, state: state ?? void 0 });
    const { authResponse } = result;
    if (options.onSuccess) {
      await options.onSuccess({
        accessToken: authResponse.accessToken,
        refreshToken: authResponse.refreshToken,
        user: authResponse.user,
        impersonator: authResponse.impersonator,
        oauthTokens: authResponse.oauthTokens,
        authenticationMethod: authResponse.authenticationMethod,
        organizationId: authResponse.organizationId,
        state: customState
      });
    }
    const redirectUrl = buildRedirectUrl(url, returnPathname);
    const sessionHeaders = extractSessionHeaders(result);
    return new Response(null, {
      status: 307,
      headers: {
        Location: redirectUrl.toString(),
        ...sessionHeaders
      }
    });
  } catch (error) {
    console.error("OAuth callback failed:", error);
    if (options.onError) {
      return options.onError({ error, request });
    }
    return new Response(JSON.stringify({
      error: {
        message: "Authentication failed",
        description: "Couldn't sign in. Please contact your organization admin if the issue persists.",
        details: error instanceof Error ? error.message : String(error)
      }
    }), { status: 500, headers: { "Content-Type": "application/json" } });
  }
}
function buildRedirectUrl(originalUrl, returnPathname) {
  const url = new URL(originalUrl);
  url.searchParams.delete("code");
  url.searchParams.delete("state");
  if (returnPathname.includes("?")) {
    const targetUrl = new URL(returnPathname, url.origin);
    url.pathname = targetUrl.pathname;
    targetUrl.searchParams.forEach((value, key) => url.searchParams.set(key, value));
  } else {
    url.pathname = returnPathname;
  }
  return url;
}
function extractSessionHeaders(result) {
  const setCookie = result?.response?.headers?.get?.("Set-Cookie");
  if (setCookie) {
    return { "Set-Cookie": setCookie };
  }
  if (result?.headers && typeof result.headers === "object") {
    return result.headers;
  }
  return {};
}
const checkSessionAction = createServerFn({
  method: "GET"
}).handler(createSsrRpc("2b41a5c96d491a63c28a578de3d4d24051e0c49a1bc852f533ba69a2b2cfe87a"));
const getAuthAction = createServerFn({
  method: "GET"
}).handler(createSsrRpc("d680fad6bf472594a3d281e01817e508c37ec861e404bdf650536bc1adbf3ec0"));
const refreshAuthAction = createServerFn({
  method: "POST"
}).inputValidator((options) => options).handler(createSsrRpc("947e9dcf13e76afdfcbe0776ab0d5d6a3d53be4cc38a7a6e46126b8a834dc98e"));
const getAccessTokenAction = createServerFn({
  method: "GET"
}).handler(createSsrRpc("8fbde53c147d0c40a3353d3a302be03bbd2d78a0555fefaa7273d58c45c684c9"));
const refreshAccessTokenAction = createServerFn({
  method: "POST"
}).handler(createSsrRpc("760f6ac025a9178fc087c5cfdaf3a82001e24863e076a45526349c20046ddb5f"));
const switchToOrganizationAction = createServerFn({
  method: "POST"
}).inputValidator((data) => data).handler(createSsrRpc("4f82c552b3fb8ae95fe0344bc1ecb36769a06605fd5dd557a2bd32973b3b48e2"));
const AuthContext = reactExports.createContext(void 0);
const getProps = (auth) => {
  return {
    user: auth && "user" in auth ? auth.user : null,
    sessionId: auth && "sessionId" in auth ? auth.sessionId : void 0,
    organizationId: auth && "organizationId" in auth ? auth.organizationId : void 0,
    role: auth && "role" in auth ? auth.role : void 0,
    roles: auth && "roles" in auth ? auth.roles : void 0,
    permissions: auth && "permissions" in auth ? auth.permissions : void 0,
    entitlements: auth && "entitlements" in auth ? auth.entitlements : void 0,
    featureFlags: auth && "featureFlags" in auth ? auth.featureFlags : void 0,
    impersonator: auth && "impersonator" in auth ? auth.impersonator : void 0
  };
};
function AuthKitProvider({ children, onSessionExpired, initialAuth }) {
  const navigate = useNavigate();
  const initialProps = getProps(initialAuth);
  const [user, setUser] = reactExports.useState(initialProps.user);
  const [sessionId, setSessionId] = reactExports.useState(initialProps.sessionId);
  const [organizationId, setOrganizationId] = reactExports.useState(initialProps.organizationId);
  const [role, setRole] = reactExports.useState(initialProps.role);
  const [roles, setRoles] = reactExports.useState(initialProps.roles);
  const [permissions, setPermissions] = reactExports.useState(initialProps.permissions);
  const [entitlements, setEntitlements] = reactExports.useState(initialProps.entitlements);
  const [featureFlags, setFeatureFlags] = reactExports.useState(initialProps.featureFlags);
  const [impersonator, setImpersonator] = reactExports.useState(initialProps.impersonator);
  const [loading, setLoading] = reactExports.useState(initialAuth ? false : true);
  const getAuth2 = reactExports.useCallback(async () => {
    setLoading(true);
    try {
      const auth = await getAuthAction();
      const props = getProps(auth);
      setUser(props.user);
      setSessionId(props.sessionId);
      setOrganizationId(props.organizationId);
      setRole(props.role);
      setRoles(props.roles);
      setPermissions(props.permissions);
      setEntitlements(props.entitlements);
      setFeatureFlags(props.featureFlags);
      setImpersonator(props.impersonator);
    } catch (error) {
      setUser(null);
      setSessionId(void 0);
      setOrganizationId(void 0);
      setRole(void 0);
      setRoles(void 0);
      setPermissions(void 0);
      setEntitlements(void 0);
      setFeatureFlags(void 0);
      setImpersonator(void 0);
    } finally {
      setLoading(false);
    }
  }, []);
  const refreshAuth = reactExports.useCallback(async ({ organizationId: organizationId2 } = {}) => {
    try {
      setLoading(true);
      const auth = await refreshAuthAction({ data: { organizationId: organizationId2 } });
      const props = getProps(auth);
      setUser(props.user);
      setSessionId(props.sessionId);
      setOrganizationId(props.organizationId);
      setRole(props.role);
      setRoles(props.roles);
      setPermissions(props.permissions);
      setEntitlements(props.entitlements);
      setFeatureFlags(props.featureFlags);
      setImpersonator(props.impersonator);
    } catch (error) {
      return error instanceof Error ? { error: error.message } : { error: String(error) };
    } finally {
      setLoading(false);
    }
  }, []);
  const handleSignOut = reactExports.useCallback(async ({ returnTo = "/" } = {}) => {
    const result = await getSignOutUrl({ data: { returnTo } });
    if (result.url) {
      window.location.href = result.url;
    } else {
      navigate({ to: returnTo });
    }
  }, [navigate]);
  const handleSwitchToOrganization = reactExports.useCallback(async (organizationId2) => {
    try {
      setLoading(true);
      const auth = await switchToOrganizationAction({ data: { organizationId: organizationId2 } });
      const props = getProps(auth);
      setUser(props.user);
      setSessionId(props.sessionId);
      setOrganizationId(props.organizationId);
      setRole(props.role);
      setRoles(props.roles);
      setPermissions(props.permissions);
      setEntitlements(props.entitlements);
      setFeatureFlags(props.featureFlags);
      setImpersonator(props.impersonator);
    } catch (error) {
      return error instanceof Error ? { error: error.message } : { error: String(error) };
    } finally {
      setLoading(false);
    }
  }, []);
  reactExports.useEffect(() => {
    if (!initialAuth) {
      getAuth2();
    }
  }, []);
  reactExports.useEffect(() => {
    if (onSessionExpired === false) {
      return;
    }
    let visibilityChangedCalled = false;
    const handleVisibilityChange = async () => {
      if (visibilityChangedCalled) {
        return;
      }
      if (document.visibilityState === "visible") {
        visibilityChangedCalled = true;
        try {
          const hasSession = await checkSessionAction();
          if (!hasSession) {
            throw new Error("Session expired");
          }
        } catch (error) {
          if (error instanceof Error && error.message.includes("Failed to fetch")) {
            if (onSessionExpired) {
              onSessionExpired();
            } else {
              window.location.reload();
            }
          }
        } finally {
          visibilityChangedCalled = false;
        }
      }
    };
    window.addEventListener("visibilitychange", handleVisibilityChange);
    window.addEventListener("focus", handleVisibilityChange);
    return () => {
      window.removeEventListener("focus", handleVisibilityChange);
      window.removeEventListener("visibilitychange", handleVisibilityChange);
    };
  }, [onSessionExpired]);
  return jsxRuntimeExports.jsx(AuthContext.Provider, { value: {
    user,
    sessionId,
    organizationId,
    role,
    roles,
    permissions,
    entitlements,
    featureFlags,
    impersonator,
    loading,
    getAuth: getAuth2,
    refreshAuth,
    signOut: handleSignOut,
    switchToOrganization: handleSwitchToOrganization
  }, children });
}
function useAuth({ ensureSignedIn = false } = {}) {
  const context = reactExports.useContext(AuthContext);
  reactExports.useEffect(() => {
    if (context && ensureSignedIn && !context.user && !context.loading) {
      context.getAuth({ ensureSignedIn });
    }
  }, [ensureSignedIn, context?.user, context?.loading, context?.getAuth]);
  if (!context) {
    throw new Error("useAuth must be used within an AuthKitProvider");
  }
  return context;
}
function decodeBase64Url(input) {
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/");
  const padding = "=".repeat((4 - base64.length % 4) % 4);
  return atob(base64 + padding);
}
function decodeJwt(token) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }
  try {
    const header = JSON.parse(decodeBase64Url(parts[0]));
    const payload = JSON.parse(decodeBase64Url(parts[1]));
    return { header, payload };
  } catch (error) {
    throw new Error(`Failed to decode JWT: ${error instanceof Error ? error.message : String(error)}`);
  }
}
const TOKEN_EXPIRY_BUFFER_SECONDS = 60;
const MIN_REFRESH_DELAY_SECONDS = 15;
const MAX_REFRESH_DELAY_SECONDS = 24 * 60 * 60;
const RETRY_DELAY_SECONDS = 300;
const jwtCookieName = "workos-access-token";
class TokenStore {
  state;
  serverSnapshot;
  constructor() {
    const initialToken = typeof window !== "undefined" ? this.getInitialTokenFromCookie() : void 0;
    this.state = {
      token: initialToken,
      loading: false,
      error: null
    };
    this.serverSnapshot = {
      token: void 0,
      loading: false,
      error: null
    };
    if (initialToken) {
      this.fastCookieConsumed = true;
      const tokenData = this.parseToken(initialToken);
      if (tokenData) {
        this.scheduleRefresh(tokenData.timeUntilExpiry);
      }
    }
  }
  listeners = /* @__PURE__ */ new Set();
  refreshPromise = null;
  refreshTimeout;
  fastCookieConsumed = false;
  subscribe = (listener) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
      if (this.listeners.size === 0 && this.refreshTimeout) {
        clearTimeout(this.refreshTimeout);
        this.refreshTimeout = void 0;
      }
    };
  };
  getSnapshot = () => this.state;
  getServerSnapshot = () => this.serverSnapshot;
  notify() {
    this.listeners.forEach((listener) => listener());
  }
  setState(updates) {
    this.state = { ...this.state, ...updates };
    this.notify();
  }
  scheduleRefresh(timeUntilExpiry) {
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = void 0;
    }
    const delay = typeof timeUntilExpiry === "undefined" ? RETRY_DELAY_SECONDS * 1e3 : this.getRefreshDelay(timeUntilExpiry);
    this.refreshTimeout = setTimeout(() => {
      void this.getAccessTokenSilently().catch(() => {
      });
    }, delay);
  }
  getRefreshDelay(timeUntilExpiry) {
    if (timeUntilExpiry <= TOKEN_EXPIRY_BUFFER_SECONDS) {
      return 0;
    }
    const idealDelay = (timeUntilExpiry - TOKEN_EXPIRY_BUFFER_SECONDS) * 1e3;
    return Math.min(Math.max(idealDelay, MIN_REFRESH_DELAY_SECONDS * 1e3), MAX_REFRESH_DELAY_SECONDS * 1e3);
  }
  deleteCookie() {
    const isSecure = window.location.protocol === "https:";
    const deletionString = isSecure ? `${jwtCookieName}=; SameSite=Lax; Max-Age=0; Secure` : `${jwtCookieName}=; SameSite=Lax; Max-Age=0`;
    document.cookie = deletionString;
  }
  getInitialTokenFromCookie() {
    if (typeof document === "undefined" || typeof document.cookie === "undefined") {
      return;
    }
    const cookies = document.cookie.split(";").reduce((acc, cookie) => {
      const [name, ...valueParts] = cookie.trim().split("=");
      if (name && valueParts.length > 0) {
        const value = valueParts.join("=");
        acc[name.trim()] = decodeURIComponent(value);
      }
      return acc;
    }, {});
    const token = cookies[jwtCookieName];
    if (!token) {
      return;
    }
    this.deleteCookie();
    return token;
  }
  consumeFastCookie() {
    if (this.fastCookieConsumed) {
      return;
    }
    if (typeof document === "undefined" || typeof document.cookie === "undefined") {
      return;
    }
    const cookies = document.cookie.split(";").reduce((acc, cookie) => {
      const [name, ...valueParts] = cookie.trim().split("=");
      if (name && valueParts.length > 0) {
        const value = valueParts.join("=");
        acc[name.trim()] = decodeURIComponent(value);
      }
      return acc;
    }, {});
    const newToken = cookies[jwtCookieName];
    if (!newToken) {
      this.fastCookieConsumed = true;
      return;
    }
    this.fastCookieConsumed = true;
    this.deleteCookie();
    if (newToken !== this.state.token) {
      return newToken;
    }
  }
  parseToken(token) {
    if (!token)
      return null;
    try {
      const { payload } = decodeJwt(token);
      const now = Math.floor(Date.now() / 1e3);
      if (typeof payload.exp !== "number") {
        return null;
      }
      const timeUntilExpiry = payload.exp - now;
      let bufferSeconds = TOKEN_EXPIRY_BUFFER_SECONDS;
      const totalTokenLifetime = payload.exp - (payload.iat || now);
      if (totalTokenLifetime <= 300) {
        bufferSeconds = 30;
      }
      const isExpiring = payload.exp < now + bufferSeconds;
      return {
        payload,
        expiresAt: payload.exp,
        isExpiring,
        timeUntilExpiry
      };
    } catch {
      return null;
    }
  }
  isRefreshing() {
    return this.refreshPromise !== null;
  }
  clearToken() {
    this.setState({ token: void 0, error: null, loading: false });
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = void 0;
    }
  }
  async getAccessToken() {
    const fastToken = this.consumeFastCookie();
    if (fastToken) {
      this.setState({ token: fastToken, loading: false, error: null });
      return fastToken;
    }
    const tokenData = this.parseToken(this.state.token);
    if (tokenData && !tokenData.isExpiring) {
      return this.state.token;
    }
    if (this.state.token && !tokenData) {
      return this.state.token;
    }
    return this.refreshTokenSilently();
  }
  async getAccessTokenSilently() {
    const fastToken = this.consumeFastCookie();
    if (fastToken) {
      this.setState({ token: fastToken, loading: false, error: null });
      const tokenData2 = this.parseToken(fastToken);
      if (tokenData2) {
        this.scheduleRefresh(tokenData2.timeUntilExpiry);
      }
      return fastToken;
    }
    const tokenData = this.parseToken(this.state.token);
    if (tokenData && !tokenData.isExpiring) {
      return this.state.token;
    }
    if (this.state.token && !tokenData) {
      return this.state.token;
    }
    return this.refreshTokenSilently();
  }
  async refreshToken() {
    return this._refreshToken(false);
  }
  async refreshTokenSilently() {
    return this._refreshToken(true);
  }
  async _refreshToken(silent) {
    if (this.refreshPromise) {
      return this.refreshPromise;
    }
    const previousToken = this.state.token;
    if (!silent) {
      this.setState({ loading: true, error: null });
    } else {
      this.setState({ error: null });
    }
    this.refreshPromise = (async () => {
      try {
        let token;
        if (!silent) {
          token = await refreshAccessTokenAction();
        } else {
          if (!previousToken) {
            token = await getAccessTokenAction();
            const tokenData2 = this.parseToken(token);
            if (token && token !== previousToken) {
              this.setState({
                token,
                loading: false,
                error: null
              });
            }
            if (!token || tokenData2 && tokenData2.isExpiring) {
              const refreshedToken = await refreshAccessTokenAction();
              if (refreshedToken) {
                token = refreshedToken;
              }
            }
          } else {
            token = await refreshAccessTokenAction();
          }
        }
        if (token !== previousToken || !silent) {
          this.setState({
            token,
            loading: false,
            error: null
          });
        }
        const tokenData = this.parseToken(token);
        if (tokenData) {
          this.scheduleRefresh(tokenData.timeUntilExpiry);
        }
        return token;
      } catch (error) {
        this.setState({
          loading: false,
          error: error instanceof Error ? error : new Error(String(error))
        });
        this.scheduleRefresh();
        throw error;
      } finally {
        this.refreshPromise = null;
      }
    })();
    return this.refreshPromise;
  }
  reset() {
    this.state = { token: void 0, loading: false, error: null };
    this.refreshPromise = null;
    this.fastCookieConsumed = false;
    if (this.refreshTimeout) {
      clearTimeout(this.refreshTimeout);
      this.refreshTimeout = void 0;
    }
    this.listeners.clear();
  }
}
const tokenStore = new TokenStore();
function useAccessToken() {
  const { user, sessionId } = useAuth();
  const userId = user?.id;
  const userRef = reactExports.useRef(user);
  userRef.current = user;
  const prevSessionRef = reactExports.useRef(sessionId);
  const prevUserIdRef = reactExports.useRef(userId);
  const tokenState = reactExports.useSyncExternalStore(tokenStore.subscribe, tokenStore.getSnapshot, tokenStore.getServerSnapshot);
  const [isInitialTokenLoading, setIsInitialTokenLoading] = reactExports.useState(() => {
    return Boolean(user && !tokenState.token && !tokenState.error);
  });
  reactExports.useEffect(() => {
    if (!user) {
      setIsInitialTokenLoading(false);
      if (prevUserIdRef.current !== void 0) {
        tokenStore.clearToken();
      }
      prevUserIdRef.current = void 0;
      prevSessionRef.current = void 0;
      return;
    }
    const sessionChanged = prevSessionRef.current !== void 0 && prevSessionRef.current !== sessionId;
    const userChanged = prevUserIdRef.current !== void 0 && prevUserIdRef.current !== userId;
    if (sessionChanged || userChanged) {
      tokenStore.clearToken();
    }
    prevSessionRef.current = sessionId;
    prevUserIdRef.current = userId;
    const currentToken = tokenStore.getSnapshot().token;
    const tokenData = currentToken ? tokenStore.parseToken(currentToken) : null;
    const willActuallyFetch = !currentToken || tokenData && tokenData.isExpiring;
    if (willActuallyFetch) {
      setIsInitialTokenLoading(true);
    }
    tokenStore.getAccessTokenSilently().catch(() => {
    }).finally(() => {
      if (willActuallyFetch) {
        setIsInitialTokenLoading(false);
      }
    });
  }, [userId, sessionId, user]);
  reactExports.useEffect(() => {
    if (!user || typeof document === "undefined") {
      return;
    }
    const refreshIfNeeded = () => {
      tokenStore.getAccessTokenSilently().catch(() => {
      });
    };
    const handleWake = (event) => {
      if (event.type !== "visibilitychange" || document.visibilityState === "visible") {
        refreshIfNeeded();
      }
    };
    document.addEventListener("visibilitychange", handleWake);
    window.addEventListener("focus", handleWake);
    window.addEventListener("online", handleWake);
    window.addEventListener("pageshow", handleWake);
    return () => {
      document.removeEventListener("visibilitychange", handleWake);
      window.removeEventListener("focus", handleWake);
      window.removeEventListener("online", handleWake);
      window.removeEventListener("pageshow", handleWake);
    };
  }, [userId, sessionId, user]);
  const getAccessToken = reactExports.useCallback(async () => {
    if (!userRef.current) {
      return void 0;
    }
    return tokenStore.getAccessToken();
  }, []);
  const refresh = reactExports.useCallback(async () => {
    if (!userRef.current) {
      return void 0;
    }
    return tokenStore.refreshToken();
  }, []);
  const isLoading = isInitialTokenLoading || tokenState.loading;
  return {
    accessToken: tokenState.token,
    loading: isLoading,
    error: tokenState.error,
    refresh,
    getAccessToken
  };
}
const appCssUrl = "/assets/app-Bx9cBZp9.css";
const fetchWorkosAuth = createServerFn({
  method: "GET"
}).handler(createSsrRpc("0360bf05551679460fd95ca0926c27cce907fb3a5c6fea18e38ca35ca1d323a7"));
const Route$4 = createRootRouteWithContext()({
  head: () => ({
    meta: [{
      charSet: "utf-8"
    }, {
      name: "viewport",
      content: "width=device-width, initial-scale=1"
    }, {
      title: "-T"
    }],
    links: [{
      rel: "stylesheet",
      href: appCssUrl
    }, {
      rel: "icon",
      href: "/convex.svg"
    }]
  }),
  component: RootComponent,
  notFoundComponent: () => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: "Not Found" }),
  beforeLoad: async (ctx) => {
    const {
      userId,
      token
    } = await fetchWorkosAuth();
    if (token) {
      ctx.context.convexQueryClient.serverHttpClient?.setAuth(token);
    }
    return {
      userId,
      token
    };
  }
});
function RootComponent() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(RootDocument, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Outlet, {}) });
}
function RootDocument({
  children
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("html", { lang: "en", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("head", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(HeadContent, {}) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("body", { children: [
      children,
      /* @__PURE__ */ jsxRuntimeExports.jsx(Scripts, {})
    ] })
  ] });
}
const Route$3 = createFileRoute("/callback")({
  server: {
    handlers: {
      GET: handleCallbackRoute()
    }
  }
});
const $$splitComponentImporter$2 = () => import("./_authenticated-BFsOu0JM.mjs");
const Route$2 = createFileRoute("/_authenticated")({
  loader: async ({
    location
  }) => {
    const {
      user
    } = await getAuth();
    if (!user) {
      const path = location.pathname;
      const href = await getSignInUrl({
        data: {
          returnPathname: path
        }
      });
      throw redirect({
        href
      });
    }
  },
  component: lazyRouteComponent($$splitComponentImporter$2, "component")
});
const $$splitComponentImporter$1 = () => import("./index-DWjRra6w.mjs");
const Route$1 = createFileRoute("/")({
  component: lazyRouteComponent($$splitComponentImporter$1, "component"),
  loader: async () => {
    const {
      user
    } = await getAuth();
    const signInUrl = await getSignInUrl();
    const signUpUrl = await getSignUpUrl();
    return {
      user,
      signInUrl,
      signUpUrl
    };
  }
});
const $$splitComponentImporter = () => import("./authenticated-D_jebEsa.mjs");
const Route = createFileRoute("/_authenticated/authenticated")({
  component: lazyRouteComponent($$splitComponentImporter, "component")
});
const CallbackRoute = Route$3.update({
  id: "/callback",
  path: "/callback",
  getParentRoute: () => Route$4
});
const AuthenticatedRoute = Route$2.update({
  id: "/_authenticated",
  getParentRoute: () => Route$4
});
const IndexRoute = Route$1.update({
  id: "/",
  path: "/",
  getParentRoute: () => Route$4
});
const AuthenticatedAuthenticatedRoute = Route.update({
  id: "/authenticated",
  path: "/authenticated",
  getParentRoute: () => AuthenticatedRoute
});
const AuthenticatedRouteChildren = {
  AuthenticatedAuthenticatedRoute
};
const AuthenticatedRouteWithChildren = AuthenticatedRoute._addFileChildren(
  AuthenticatedRouteChildren
);
const rootRouteChildren = {
  IndexRoute,
  AuthenticatedRoute: AuthenticatedRouteWithChildren,
  CallbackRoute
};
const routeTree = Route$4._addFileChildren(rootRouteChildren)._addFileTypes();
function getRouter() {
  const CONVEX_URL = "https://focused-puffin-767.eu-west-1.convex.cloud";
  const convex = new ConvexReactClient(CONVEX_URL);
  const convexQueryClient = new ConvexQueryClient(convex);
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        queryKeyHashFn: convexQueryClient.hashFn(),
        queryFn: convexQueryClient.queryFn(),
        gcTime: 5e3
      }
    }
  });
  convexQueryClient.connect(queryClient);
  const router2 = createRouter({
    routeTree,
    defaultPreload: "intent",
    scrollRestoration: true,
    defaultPreloadStaleTime: 0,
    // Let React Query handle all caching
    defaultErrorComponent: (err) => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: err.error.stack }),
    defaultNotFoundComponent: () => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "not found" }),
    context: { queryClient, convexClient: convex, convexQueryClient },
    Wrap: ({ children }) => /* @__PURE__ */ jsxRuntimeExports.jsx(AuthKitProvider, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(ConvexProviderWithAuth, { client: convexQueryClient.convexClient, useAuth: useAuthFromWorkOS, children }) })
  });
  setupRouterSsrQueryIntegration({ router: router2, queryClient });
  return router2;
}
function useAuthFromWorkOS() {
  const { loading, user } = useAuth();
  const { getAccessToken, refresh } = useAccessToken();
  const fetchAccessToken = reactExports.useCallback(
    async ({ forceRefreshToken }) => {
      if (!user) {
        return null;
      }
      if (forceRefreshToken) {
        return await refresh() ?? null;
      }
      return await getAccessToken() ?? null;
    },
    [user, refresh, getAccessToken]
  );
  return reactExports.useMemo(
    () => ({
      isLoading: loading,
      isAuthenticated: !!user,
      fetchAccessToken
    }),
    [loading, user, fetchAccessToken]
  );
}
const router = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  getRouter
}, Symbol.toStringTag, { value: "Module" }));
export {
  Route$1 as R,
  router as r,
  useAuth as u
};
