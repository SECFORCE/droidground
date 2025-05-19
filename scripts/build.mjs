$.verbose = true;

await $`npm run scrcpy`;
await $`npm run companion`;
await $`npm run build:setup`;
await $`npm run build:client`;
await $`npm run build:server`;
await $`npm run copy-files`;

await fs.copy("resources/scrcpy-server.jar", "dist/resources/scrcpy-server.jar");
await fs.copy("resources/droidground-companion.dex", "dist/resources/droidground-companion.dex");
