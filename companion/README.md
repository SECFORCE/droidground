# 🤖 DroidGround Companion

This sub-project is heavily inspired the [aya server](https://github.com/liriliri/aya/tree/master/server) which works the same way as the [scrcpy server](https://github.com/Genymobile/scrcpy): a _Java_ application that can be run on _Android_ because the classes are [dexed](<https://en.wikipedia.org/wiki/Dalvik_(software)>). An application built in this way can be run with the following command:

```
adb shell CLASSPATH=/data/local/tmp/classes.dex app_process / my.package.MainClass
```

## 🤝 Communication

The application waits for a connection on the `droidground` UNIX abstract namespace socket and communicates with the client using `protobuf`.
The application currently supports the following methods:

- `getVersion`: which returns the value of `BuildConfig.VERSION_NAME`
- `getPackageInfos`: which returns structured info about the applications
- `getAttackSurfaces`: which returns the exported activities, broadcast receivers, services and content providers for the requested applications.

## ✍ Usage

1. Build the Android app server:

   ```bash
   ./gradlew assembleRelease
   ```

2. Push the server binary to the device:

   ```bash
   adb push droidground-companion.dex /data/local/tmp
   ```

3. Start the companion app:

   ```bash
   adb shell CLASSPATH=/data/local/tmp/droidground-companion.dex app_process /system/bin com.secforce.droidground.Server
   ```

4. The server listens for incoming protobuf-based client connections (on `localabstract:droidground`).

## 🙏 Acknowledgements

This wouldn't exist if it wasn't for [aya](https://github.com/liriliri/aya) and [scrcpy](https://github.com/Genymobile/scrcpy).
