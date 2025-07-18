
#!/usr/bin/env bash

rm multi-step-flag.apk
rm multi-step-flag.apk*
wget https://github.com/SECFORCE/droidground-samples/releases/download/v0.1.2/multi-step-flag.apk
adb shell pm uninstall com.droidground.multistep
echo "Sleep for 2 seconds before installing app"
sleep 2
echo "Installing app..."

while true; do
    adb install ./multi-step-flag.apk
    if [ $? -eq 0 ]; then
        echo "Install command succeeded!"
        break
    else
        echo "Install command failed. Retrying in 3 seconds..."
        sleep 3
    fi
done