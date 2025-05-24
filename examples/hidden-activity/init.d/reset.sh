
#!/usr/bin/env bash

adb shell pm uninstall com.droidground.hiddenactivity
echo "Sleep for 2 seconds before installing app"
sleep 2
echo "Installing app..."
# No need to download again the apk
adb install ./hidden-activity-flag.apk
echo "Install command executed"