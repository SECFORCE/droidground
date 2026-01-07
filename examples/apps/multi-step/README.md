# Multi Step

This example showcases a more realistic intent-based CTF challenge where the user has to develop an exploit application in order to get the flag.
The target application is downloaded from the [samples](https://github.com/SECFORCE/droidground-samples) and it contains an exported activity with a state machine within it. The goal of the player is to send the appropriate intents in the correct order to reach the final state and get the flag.

This example showcases the _App Manager_ feature which allows to install and run exploit applications. Since the flag is actively displayed on the screen, challenges like this one would require the organizers to either queue the access to DroidGround or spawn different instances for each team. For a more cost-effective solution take a look at [net-multi-step](../net-multi-step/).
