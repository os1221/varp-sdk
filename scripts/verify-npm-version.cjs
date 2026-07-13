#!/usr/bin/env node

const { execFileSync } = require("node:child_process");

const minimum = [11, 5, 1];
const rawVersion = execFileSync("npm", ["--version"], { encoding: "utf8" }).trim();
const match = /^(\d+)\.(\d+)\.(\d+)/.exec(rawVersion);

if (!match) {
  console.error(`npm version verification failed: could not parse ${rawVersion}`);
  process.exit(1);
}

const actual = match.slice(1).map(Number);
let comparison = 0;
for (let index = 0; index < minimum.length; index += 1) {
  if (actual[index] === minimum[index]) continue;
  comparison = actual[index] > minimum[index] ? 1 : -1;
  break;
}
const supported = comparison >= 0;

if (!supported) {
  console.error(`npm version verification failed: ${rawVersion} is older than 11.5.1`);
  process.exit(1);
}

console.log(`npm ${rawVersion} satisfies the trusted-publishing minimum (11.5.1)`);
