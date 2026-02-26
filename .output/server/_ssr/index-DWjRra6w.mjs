import { j as jsxRuntimeExports } from "../_chunks/_libs/react.mjs";
import { L as Link } from "../_chunks/_libs/@tanstack/react-router.mjs";
import { c as convexQuery } from "../_chunks/_libs/@convex-dev/react-query.mjs";
import { u as useSuspenseQuery } from "../_chunks/_libs/@tanstack/react-query.mjs";
import { R as Route$1, u as useAuth } from "./router-BZNMmnil.mjs";
import { A as Authenticated, U as Unauthenticated, d as anyApi, u as useMutation, e as componentsGeneric } from "../_libs/convex.mjs";
import "../_chunks/_libs/@tanstack/router-core.mjs";
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
import "../_chunks/_libs/@tanstack/query-core.mjs";
import "../_chunks/_libs/@tanstack/react-router-ssr-query.mjs";
import "../_chunks/_libs/@tanstack/router-ssr-query-core.mjs";
import "./server-functions-D20kG-HZ.mjs";
import "./index.mjs";
import "node:async_hooks";
import "../_libs/h3-v2.mjs";
import "../_libs/rou3.mjs";
import "../_libs/srvx.mjs";
import "./authkit-loader-BpUdXche.mjs";
import "../_chunks/_libs/@workos/authkit-session.mjs";
import "../_chunks/_libs/@workos-inc/node.mjs";
import "../_libs/iron-webcrypto.mjs";
import "../_libs/uint8array-extras.mjs";
import "../_libs/jose.mjs";
import "./auth-helpers-CNd1dCOr.mjs";
const api = anyApi;
componentsGeneric();
function Home() {
  const {
    user,
    signInUrl,
    signUpUrl
  } = Route$1.useLoaderData();
  return /* @__PURE__ */ jsxRuntimeExports.jsx(HomeContent, { user, signInUrl, signUpUrl });
}
function HomeContent({
  user,
  signInUrl,
  signUpUrl
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "sticky top-0 z-10 bg-background p-4 border-b-2 border-slate-200 dark:border-slate-800 flex flex-row justify-between items-center", children: [
      "Convex + TanStack Start + WorkOS",
      user && /* @__PURE__ */ jsxRuntimeExports.jsx(UserMenu, { user })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("main", { className: "p-8 flex flex-col gap-8", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-4xl font-bold text-center", children: "Convex + TanStack Start + WorkOS" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Authenticated, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Content, {}) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Unauthenticated, { children: /* @__PURE__ */ jsxRuntimeExports.jsx(SignInForm, { signInUrl, signUpUrl }) })
    ] })
  ] });
}
function SignInForm({
  signInUrl,
  signUpUrl
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-8 w-96 mx-auto", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Log in to see the numbers" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: signInUrl, children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "bg-foreground text-background px-4 py-2 rounded-md", children: "Sign in" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: signUpUrl, children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "bg-foreground text-background px-4 py-2 rounded-md", children: "Sign up" }) })
  ] });
}
function Content() {
  const {
    data: {
      viewer,
      numbers
    }
  } = useSuspenseQuery(convexQuery(api.myFunctions.listNumbers, {
    count: 10
  }));
  const addNumber = useMutation(api.myFunctions.addNumber);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-8 max-w-lg mx-auto", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
      "Welcome ",
      viewer,
      "!"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Click the button below and open this page in another window - this data is persisted in the Convex cloud database!" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: "bg-foreground text-background text-sm px-4 py-2 rounded-md", onClick: () => {
      void addNumber({
        value: Math.floor(Math.random() * 10)
      });
    }, children: "Add a random number" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
      "Numbers: ",
      numbers.length === 0 ? "Click the button!" : numbers.join(", ")
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
      "Edit",
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-sm font-bold font-mono bg-slate-200 dark:bg-slate-800 px-1 py-0.5 rounded-md", children: "convex/myFunctions.ts" }),
      " ",
      "to change your backend"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
      "Edit",
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "text-sm font-bold font-mono bg-slate-200 dark:bg-slate-800 px-1 py-0.5 rounded-md", children: "src/routes/index.tsx" }),
      " ",
      "to change your frontend"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
      "See",
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx(Link, { to: "/authenticated", className: "underline hover:no-underline", children: "/authenticated" }),
      " ",
      "for an example of a page only available to authenticated users."
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-lg font-bold", children: "Useful resources:" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 w-1/2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ResourceCard, { title: "Convex docs", description: "Read comprehensive documentation for all Convex features.", href: "https://docs.convex.dev/home" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ResourceCard, { title: "Stack articles", description: "Learn about best practices, use cases, and more from a growing collection of articles, videos, and walkthroughs.", href: "https://stack.convex.dev" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 w-1/2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ResourceCard, { title: "Templates", description: "Browse our collection of templates to get started quickly.", href: "https://www.convex.dev/templates" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ResourceCard, { title: "Discord", description: "Join our developer community to ask questions, trade tips & tricks, and show off your projects.", href: "https://www.convex.dev/community" })
        ] })
      ] })
    ] })
  ] });
}
function ResourceCard({
  title,
  description,
  href
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 bg-slate-200 dark:bg-slate-800 p-4 rounded-md h-28 overflow-auto", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href, className: "text-sm underline hover:no-underline", children: title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs", children: description })
  ] });
}
function UserMenu({
  user
}) {
  const {
    signOut
  } = useAuth();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm", children: user.email }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: () => signOut(), className: "bg-red-500 text-white px-3 py-1 rounded-md text-sm hover:bg-red-600 cursor-pointer", children: "Sign out" })
  ] });
}
export {
  Home as component
};
