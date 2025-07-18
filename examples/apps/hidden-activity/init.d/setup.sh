
#!/usr/bin/env bash

rm hidden-activity-flag.apk
rm hidden-activity-flag.apk*
wget https://github.com/SECFORCE/droidground-samples/releases/download/v0.1.2/hidden-activity-flag.apk
adb shell pm uninstall com.droidground.hiddenactivity
echo "Sleep for 2 seconds before installing app"
sleep 2
echo "Installing app..."

while true; do
    adb install ./hidden-activity-flag.apk
    if [ $? -eq 0 ]; then
        echo "Install command succeeded!"
        break
    else
        echo "Install command failed. Retrying in 3 seconds..."
        sleep 3
    fi
done