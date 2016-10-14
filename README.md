# Decryptonite
**Decryptonite** is a tool that uses heuristics and behavioural analysis to monitor for and stop [ransomware](https://www.microsoft.com/en-us/security/portal/mmpc/shared/ransomware.aspx). 

## Features
* Monitors entire hard disk for suspicious IO behaviour
* Whitelists known-good and system processes
* Calculates a process' complete threat level by combining child suspicion with parent
* Watches process' file system writes per second
* Kills suspicious processes immediately if it passes the threshold
* Low memory and CPU footprint

## Installation
* Install requirements
	* [Microsoft Visual Studio 2015](https://www.visualstudio.com/downloads/)
	* [Windows Driver Kit 8.1](https://www.microsoft.com/en-us/download/details.aspx?id=42273)
	* [Windows Driver Kit 10](https://developer.microsoft.com/en-us/windows/hardware/windows-driver-kit)
	* [Windows SDK 10](https://developer.microsoft.com/en-us/windows/downloads/windows-10-sdk)
	* Windows 7 x64 (The project has been fully tested on Win7. You're welcome to install it on other 64 bit Windows operating systems after Vista. It *should* work.)
	* To run the executable without Visual Studios install: [Visual C++ Redistributable for Visual Studio 2015](https://www.microsoft.com/en-us/download/details.aspx?id=48145)
* Clone the respository: `git clone https://github.com/DecryptoniteTeam/Decryptonite`
* Open the project (decryptonite.sln) in Visual Studios
* In Visual Studios its time to build the executable and driver:
	* Navigate to Build -> Configuration Manager
	* Change the platform from "Win32" to "x64" for both projects
	* Browse to Build -> Build Solution
	* **When you get errors please open a ticket** ... Compiling and building drivers is definitely not a straightforward process. 
* Disable [Windows Signed Driver Enforcement](https://msdn.microsoft.com/en-us/windows/hardware/drivers/install/kernel-mode-code-signing-policy--windows-vista-and-later-):
	* [Windows 7/8/Vista](https://www.raymond.cc/blog/loading-unsigned-drivers-in-windows-7-and-vista-64-bit-x64/)
	* [Windows 10](http://windowsreport.com/driver-signature-enforcement-windows-10/)
* Setting up Decryptonite:
	* Install the driver:
		* Browse to containing folder
		* Right-click "decryptonite.inf" and click "Install"
	* Load the driver:
		* Open PowerShell.exe with Administrative Privileges
		* Execute `fltMc.exe load decryptonite`
	* Finally... We can run the executable!

## Usage
When you've successfully built the project, you can run the executable directly with an Administrative PowerShell - `.\decryptonite.exe`
![](http://imgur.com/a2wbXrX.png)

That's all the setup required! Decryptonite will automatically detect and attach to the "C:\\" drive. If you decide to run either ransomware or executables with valid digital signatures, the output will resemble the following:
![Easter egg](http://imgur.com/thYmRiw.png "Decryptonite")

To configure the application's behaviour: hit `enter` to bring up the prompt `>` and type `help`
![](http://imgur.com/qcVJH7L.png)
### Commands
* `/a [drive]` attach Decryptonite to another drive e.g. "D:"
* `/d [drive] ` stop Decryptonite from monitoring on a given drive
* `/l` - lists all drives that Decryptonite is attached to
* `/f [file name]` redirect all output to a given file
* `/p` Decryptonite will run, it will monitor, but it won't kill any processes
* `/v` makes Decryptonite more verbose
* `/x` makes Decryptonite much more verbose
* `exit` exits the application

## Contribute
Spotted a bug? Want to add features? Increase the performance?

Open an [issue](https://github.com/DecryptoniteTeam/Decryptonite/issues) or submit a [pull request](https://github.com/DecryptoniteTeam/Decryptonite/pulls)!

## Authors
The Decryptonite team includes:
* [Adam Greenhill](https://github.com/AdamGreenhill)
* [Peter Chmura](https://ca.linkedin.com/in/peter-chmura-90021979)
* [Christina Kang](https://ca.linkedin.com/in/christinakang18)
* [Desiree McCarthy](https://#)

## Credits
A big thanks to [Troy D. Hanson](https://troydhanson.github.io/) for his development of the open source libraries [UTHash](https://troydhanson.github.io/uthash/) and [UTArray](https://troydhanson.github.io/uthash/utarray.html).

Additionally, a big thanks goes to Microsoft for their development of the open source file system minifilter driver project [MiniSpy](https://github.com/Microsoft/Windows-driver-samples/tree/master/filesys/miniFilter/minispy).

## License
This project is released under [The Microsoft Public License](LICENSE).