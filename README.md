# empty_list tester

Recently there has been a lot of debate on the Th0r jailbreak by pwned4ever. He is getting involved in arguments with known developers. People claim his jailbreak's modified empty_list exploit has a very high success rate but that is still a question for devs because they have never tried it for many reasons: The jailbreak is just a copy of Electra with a modified name and UI. That is 100% true and not just that but it's also closed-source, meaning that it breaks the license of Electra, can be broken, can have malware and that you can't use it **temporarily**, i.e. testing its exploit while not having to erase the previous jailbreak. I didn't want to use it either so what I did was converting it into a loadable dylib and running **only** the exploit part of it, to test the success rate; it worked 4 out of 10 tries, which for me personally was better than the other versions of empty_list and the latest th0r version worked 14 out of 20 tries, even better than before; but since that is not a very good test I decided to share this with people. **Now since I can't link to th0r or redistribute it for legal reasons**, I decided not to hardcode offsets but make a small offsetfinder based on the work of xerub. That was quite fun to do. Anyway, test this and tell me how many times out of how many tries this worked for you. **This will not run any code except for the empty_list exploit**.

## Instructions
- Grab a copy of Th0r or Electra
- Rename ".ipa" to ".zip" & extract
- Open Payload and get the main binary, should be named "Th0r"/"Electra"
- Grab dylibify from http://github.com/jakeajames/dylibify, available for macOS & jailbroken iOS.
- Run (where /path/to/el.dylib is the desired output path; must be named el.dylib):

      dylibify /path/to/binary /path/to/el.dylib
- Download this project and put el.dylib inside the 'Th0r_empty_list' directory
- Install the app in your device

## Running

After installing app, you'll see a button with the amount of successful tries and all the tries, like this for example: "5/10" meaning "10 tries; 5 successful". Clicking that will trigger the exploit. **It is recommended:** to do a clean reboot and then leave your device idle for one minute before each try. At the end, just share those stats with me and for comparsion you could reinstall the app and try the same thing with Electra VFS, that is also supported.

## Issues
If the try counter doesn't add one when kernel panics, tell me.
