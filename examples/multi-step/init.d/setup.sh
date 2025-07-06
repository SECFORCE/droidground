
#!/usr/bin/env bash

wget https://github.com/SECFORCE/droidground-samples/releases/download/v0.1.1/multi-step-flag.apk
adb shell pm uninstall com.droidground.multistep
echo "Sleep for 2 seconds before installing app"
sleep 2
echo "Installing app..."
adb install ./multi-step-flag.apk
echo "Install command executed"