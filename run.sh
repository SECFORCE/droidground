#!/usr/bin/env bash

adb kill-server
adb start-server

# Check if the DG_DEVICE_TYPE environment variable is set to "network"
if [ "$DG_DEVICE_TYPE" == "network" ]; then
  echo "DG_DEVICE_TYPE is set to 'network'. Trying to connect to the Android device..."

  while true; do
    adb connect $DG_DEVICE_HOST:$DG_DEVICE_PORT

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
  echo "DG_DEVICE_TYPE is not 'network'. Skipping adb connect."
fi

node server