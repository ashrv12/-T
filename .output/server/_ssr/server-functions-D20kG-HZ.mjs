import { c as createServerFn, T as TSS_SERVER_FUNCTION, a as getServerFnById } from "./index.mjs";
const createSsrRpc = (functionId, importer) => {
  const url = "/_serverFn/" + functionId;
  const serverFnMeta = { id: functionId };
  const fn = async (...args) => {
    const serverFn = await getServerFnById(functionId);
    return serverFn(...args);
  };
  return Object.assign(fn, {
    url,
    serverFnMeta,
    [TSS_SERVER_FUNCTION]: true
  });
};
const getSignOutUrl = createServerFn({
  method: "POST"
}).inputValidator((options) => options).handler(createSsrRpc("da5afb9bdc4a4c4273a3e985c6a21506be405bd882083153198c354906cc9671"));
createServerFn({
  method: "POST"
}).inputValidator((options) => options).handler(createSsrRpc("89c05eca9d1a26569b5729c9f53081a3d87100033ce9867c75c50046d7e4fd84"));
const getAuth = createServerFn({
  method: "GET"
}).handler(createSsrRpc("e206de2e2ad20d09cf25c2bcf19972cbd4a9f45957227b050a63f26acbd0c3c0"));
createServerFn({
  method: "GET"
}).inputValidator((options) => options).handler(createSsrRpc("23de6bed10ade3fd06436c64113f12c9c17b5732e4394a29dd4bb78628937c8c"));
const getSignInUrl = createServerFn({
  method: "GET"
}).inputValidator((data) => data).handler(createSsrRpc("859354b50f88ba44a183938ef69b68472bfaeeb450c54e1b943f450acbb603d4"));
const getSignUpUrl = createServerFn({
  method: "GET"
}).inputValidator((data) => data).handler(createSsrRpc("6682d12152eb1079fb9ecabcc55f8a5871370cee230d6597b5ee1cca2e521289"));
createServerFn({
  method: "POST"
}).inputValidator((data) => data).handler(createSsrRpc("c9b8e0dd9c7949a3bc8661897cf67ed60b574436f842b90d08ef1bf21a94eb17"));
export {
  getSignOutUrl as a,
  getSignInUrl as b,
  createSsrRpc as c,
  getSignUpUrl as d,
  getAuth as g
};
