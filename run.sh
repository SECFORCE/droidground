#!/usr/bin/env bash

adb kill-server
adb start-server

# Check if the DROIDGROUND_DEVICE_TYPE environment variable is set to "network"
if [ "$DROIDGROUND_DEVICE_TYPE" == "network" ]; then
  echo "DROIDGROUND_DEVICE_TYPE is set to 'network'. Trying to connect to the Android device..."

  while true; do
    adb kill-server
    adb start-server
    adb connect $DROIDGROUND_DEVICE_HOST:$DROIDGROUND_DEVICE_PORT

    # List connected devices
    CONNECTED=$(adb devices | grep -w "device")

    if [[ -n "$CONNECTED" ]]; then
      echo "Device connected successfully!"
      break
    else
      echo "No device connected. Retrying in 3 seconds..."
      sleep 3
    fi
  done
else
  echo "DROIDGROUND_DEVICE_TYPE is not 'network'. Skipping adb connect."
fi

node server