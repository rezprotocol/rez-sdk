export function makeTestRuntimeOwnership() {
  let activeOwner = null;
  let runtimeEpoch = 0;
  return async function acquireRuntimeOwnership() {
    if (activeOwner !== null) {
      const err = new Error("delivery runtime already active");
      err.code = "DELIVERY_RUNTIME_ALREADY_ACTIVE";
      throw err;
    }
    const owner = {};
    activeOwner = owner;
    runtimeEpoch += 1;
    return {
      runtimeEpoch,
      assertActive() {
        if (activeOwner !== owner) {
          const err = new Error("delivery runtime ownership was lost");
          err.code = "DELIVERY_RUNTIME_FENCED";
          throw err;
        }
      },
      async release() {
        if (activeOwner === owner) activeOwner = null;
      },
    };
  };
}

export function withTestRuntimeOwnership(provider) {
  provider.acquireRuntimeOwnership = makeTestRuntimeOwnership();
  return provider;
}
