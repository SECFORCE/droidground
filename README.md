<h1 align="center">
  <br>
    <img src="./logo.png" alt= "droidground" width="200px">
</h1>
<p align="center">
    <b>DroidGround</b>
<p>

In traditional Capture the Flag (CTF) challenges, it's common to hide flags in files on a system, requiring attackers to exploit vulnerabilities to retrieve them. However, in the Android world, this approach doesn't work well. APK files are easily downloadable and reversible, so placing a flag on the device usually makes it trivial to extract using static analysis or emulator tricks. This severely limits the ability to create realistic, runtime-focused challenges.
DroidGround is designed to solve this problem.
It is a custom-built platform for hosting Android mobile hacking challenges in a controlled and realistic environment, where attackers are constrained just enough to require solving challenges in the intended way.
Importantly, participants are jailed inside the app environment. The modularity of the tool allows to set if the user can or cannot spawn a shell, read arbitrary files, or sideload tools. Everything can be setup so that the only way to retrieve the flag is through understanding and exploiting the app itself, just like on a real, non-rooted device.