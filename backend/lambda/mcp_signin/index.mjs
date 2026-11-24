import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { createSignInService } from "@io-kit/mcp/as";
import { buildConfig, stateKeyParam } from "./config.mjs";

// Cold-start state: the fleet registry and the state key are read once and cached.
let servicePromise;

async function readStateKey() {
  // @aws-sdk/client-ssm ships in the nodejs20.x runtime, so it is not a package dependency.
  const { SSMClient, GetParameterCommand } = await import("@aws-sdk/client-ssm");
  const out = await new SSMClient({}).send(new GetParameterCommand({ Name: stateKeyParam(), WithDecryption: true }));
  return out.Parameter.Value;
}

function init() {
  servicePromise ??= (async () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const fleet = JSON.parse(readFileSync(join(here, "fleet.json"), "utf8"));
    return createSignInService(buildConfig({ fleet, stateKey: await readStateKey() }));
  })().catch((e) => {
    servicePromise = undefined; // do not cache a failed cold start
    throw e;
  });
  return servicePromise;
}

export const handler = async (event) => (await init()).lambda(event);
