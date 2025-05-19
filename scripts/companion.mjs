$.verbose = true;
cd("companion");
await $`./gradlew assembleRelease`;
cd("..");
await fs.copy("companion/droidground-companion.dex", "resources/droidground-companion.dex");
