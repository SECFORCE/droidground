
#!/usr/bin/env bash

wget https://github.com/SECFORCE/droidground-samples/releases/download/v0.1.0/hidden-activity-flag.apk
adb shell pm uninstall com.droidground.hiddenactivity
echo "Sleep for 2 seconds before installing app"
sleep 2
echo "Installing app..."
adb install ./hidden-activity-flag.apk
echo "Install command executed"