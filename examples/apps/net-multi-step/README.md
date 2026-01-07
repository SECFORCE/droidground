# Network Multi Step

This folder contains a **realistic** intent-based challenge setup where the user has to develop an exploit application in order to get the flag.
The target application is downloaded from the [samples](https://github.com/SECFORCE/droidground-samples) and it contains and exported activity with a state machine within it. If the player is able to get to the final step a `GET` request will be performed to a URL that can be set by the player. By also leveraging the **Exploit Server** feature available when setting the `DROIDGROUND_NUM_TEAMS` env variable and adding a `dns` container that does not allow to reach external hosts it is possible to deploy a cost-effective challenge which can be easily replicated for real-world CTF challenges.

The workflow is:

1. The team builds an exploit app and installs it by using the assigned _Team Token_. It won't be possible to start the app without knowing the Team Token (of course it will be possible to start App A from App B via an explicit intent).
2. The exploit app uses the Exploit Server IP/Host (if DNS is set) to exfiltrate the flag
3. Enjoy the flag!

This example sets up a DNS server using `dockurr/dnsmasq` that only provides an IP address for the `droidground` host.

If you are worried that other teams may start your exploit app (via another app thorugh an explicit intent) and unrightfully retrieve the flag you may either:

- Reset the state right after running it
- Add the `android.permission.DUMP` permission to the launcher activity so that other apps won't be able to start it. Here is an example:

  ```xml
  <activity
    android:name=".MainActivity"
    android:exported="true"
    android:permission="android.permission.DUMP">
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />

        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>
  </activity>
  ```
