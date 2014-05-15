========
Overview
========
OpenDLP is a free and open source, agent-based, centrally-managed, massively
distributable data loss prevention tool released under the GPL. OpenDLP can
identify sensitive data at rest on thousands of systems simultaneously. OpenDLP
has two components:

Web Application
- Automatically deploy and start agents over SMB
- When done, automatically stop, uninstall, and delete agents over SMB
- Pause, resume, and forcefully uninstall agents in an entire scan or on
  individual systems
- Concurrently and securely receive results from hundreds or thousands of
  deployed agents over two-way-trusted SSL connection
- Create Perl-compatible regular expressions (PCREs) for finding sensitive data
  at rest
- Create reusable profiles for scans that include whitelisting or blacklisting directories and file extensions
- Review findings and identify false positives
- Export results as XML
- Written in Perl with MySQL backend 

Agent
- Runs on Windows 2000 and later systems
- Written in C with no .NET Framework requirements
- Runs as a Windows Service at low priority so users do not see or feel it
- Resumes automatically upon system reboot with no user interaction
- Securely transmit results to web application at user-defined intervals over
  two-way-trusted SSL connection
- Uses PCREs to identify sensitive data inside files
- Performs additional checks on potential credit card numbers to reduce false
  positives
- Can read inside ZIP files, including Office 2007 and OpenOffice files
- Limits itself to a percent of physical memory so there is no thrashing when
  processing large files
- Can be used with existing Meterpreter sessions

Agentless Database Scans
In addition to performing data discovery on Windows operating systems, OpenDLP
also supports performing agentless data discovery against the following
databases:
- Microsoft SQL server
- MySQL

For Microsoft SQL server, OpenDLP supports authenticating either with SQL server
credentials (the "sa" account, for example) or with Windows OS (domain)
credentials.

Agentless File System and File Share Scans
With OpenDLP 0.4, one can perform the following scans:
- Agentless Windows file system scan (over SMB)
- Agentless Windows share scan (over SMB)
- Agentless UNIX file system scan (over SSH using sshfs) 

OpenDLP is copyright Andrew Gavin (andrew.opendlp@gmail.com) 2009-2012.


============================== ATTENTION =================================
You are not the only person downloading this VM and using it. Keep in mind
that the default authentication credentials used in the VM's configuration
could become widely known.

It is your responsibility to reconfigure the authentication credentials as
you see fit. Andrew Gavin (and any other OpenDLP contributers or
developers) are not responsible for any data loss as a result of using
this VM.

Additionally, other people will have the private SSL keys. They can use
this information to conduct man-in-the-middle attacks against your agents
as they phone home. If you are concerned about this, change your keys!
==========================================================================

1. This image was built on VirtualBox 4.0.12. VirtualBox is open source and
   freely available for many operating systems at the following URL:

   http://www.virtualbox.org


2. To extract the VM, download all the VM files and open the first one inside
   7-zip (http://www.7-zip.org). It is a multi-part archive, so 7-zip will
   automatically continue to the next files.


3. The operating system's authentication credentials are:
   username: opendlp
   password: opendlp
   You will want to change this password if you enable SSH.


4. Copy "sc.exe" from a 32-bit Windows 2000/XP system and put it in
   "/var/www/OpenDLP/bin/". I cannot distribute this binary as it is copyrighted
   by Microsoft.


5. Import the "client.p12" into your browser.
   A. Firefox
      1) Go to Firefox's preferences
      2) Go to the "Advanced" tab
      3) Go to the "Encryption" sub-tab
      4) Click the "View Certificates" button
      5) In the "Certificate Manager" window, go to the "Your Certificates"
	 tab
      6) Click the "Import..." button
      7) Find the "client.p12" file and import it


6. The MySQL root password is "opendlp".
   If, for some reason, you plan to expose the MySQL daemon to a
   non-localhost interface, or if you share the local operating system's
   authentication credentials with other people, change this password.
   This account has access to the unencrypted domain administrator
   authentication credentials. YOU HAVE BEEN WARNED.


7. The MySQL "OpenDLP" user's credentials are:
   username: OpenDLP
   password: OpenDLPpassword
   If, for some reason, you plan to expose the MySQL daemon to a
   non-localhost interface, or if you share the local operating system's
   authentication credentials with other people, change this password.
   This account has access to the unencrypted domain administrator
   authentication credentials. YOU HAVE BEEN WARNED.


8. The Apache basic authentication credentials for administrators
   to view results are:
   username: dlpuser
   password: OpenDLP
   Remember that you must also import the "client.p12" file to
   every administrator. They must import this file into their browsers
   in order to communicate with the web server.


9. The Apache basic authentication credentials for agents, used to
   submit results, are:
   Upload URL username: ddt
   Upoad URL password: OpenDLPagent
   You will need to use these values when creating profiles. In the
   profile editor, these values correspond to the "phonehomeuser"
   and "phonehomepassword" values.


10. Browse to the following URL to begin using the web application:

    https://ip/OpenDLP/index.html


11. Metasploit: Basic Guidance
	A. On your Metasploit box, start msfrpcd:
	   msfrpcd -S -a non-loopback_address -P a_password -U a_username -f
		1) It is important to specify a non-loopback address so OpenDLP
		   can connect to it.
		2) By default, msfrpcd uses loopback, which will not work.
	B. On your Metasploit box, start msfgui
	C. Inside msfgui, go to the menu "File" -> "Connect to msfrpcd"
	D. Populate username, password, host, and port; click "Connect"
	E. Exploit a Windows box. The following is a basic example:
		1) Go to the menu "Exploits" -> "windows" -> "smb" -> "psexec"
		2) A new window will display titled "Microsoft Windows
		   Authenticated User Code Execution"
		3) Select the "Automatic" target radio button
		4) Select the "windows" -> "meterpreter" -> "reverse_tcp"
		   payload (it is required to use a "meterpreter" payload for
		   OpenDLP to work)
		5) Populate the "RHOST", "SMBUser", "SMBPass", and "SMBDomain"
		   fields
		6) Click "Run Exploit" directly below the "RHOST" field
	F. One-time only: Copy the OpenDLP Ruby post module file
	   "OpenDLP/metasploit_modules/opendlp.rb" to your Metasploit box. It
	   should go in Metasploit's directory
	   "msf3/modules/post/windows/gather"
	   (Backtrack 5 users: This directory is
	   "/opt/metasploit/msf3/modules/post/windows/gather")
	G. One-time only: Copy the OpenDLP deployment files located in 
	   "/var/www/OpenDLP/bin/" on the OpenDLP machine to a path on the 
	   metasploit machine. This includes OpenDLPz.exe, StrFile.exe, 
	   client.pem, server.pem, and sc.exe (retrieved from a Windows XP
	   box as detailed above). 
	H. In your OpenDLP web browser, create a new profile for "Metasploit
	   (agent) - Post Module deployment"
		1) Populate the "Profile Name", "Metasploit Host",
		   "Metasploit Port", "Metasploit User", and "Metasploit Password".
		2) Populate the "Path to OpenDLP files" with the location of the 
		   deployment files from step "G" above.
		3) Populate the remainder of the profile's information (Note:
		   The fields "Username" and "Password" should be left blank)
		4) Submit the profile
	I. In your OpenDLP browser, go to "Scans" -> "Start New Scan"
		1) Populate a unique scan name
		2) Select the newly-created Metasploit profile from the
		   "Profile" drop-down
		3) Click "Get Sessions"
		4) A table of sessions will display. Select as many checkboxes
		   as needed to launch the scans.
		5) Click "Start Scan"
			a) Be careful to not launch scans more than once per IP
			   address.
			b) Scan deployment may take 30 or more seconds as
			   OpenDLP talks to Metasploit and as Metasploit talks
			   to the victim Windows systems.
	J. If you have any problems with this, reference the following URL that
	   discusses how to use the Metasploit Framework XMLRPC API:
	   https://community.rapid7.com/docs/DOC-1287
	K. More Guidance
		1) Meterpreter deployment: Requires standard deployment files
		   (opendlpz.exe, client.pem, server.pem) plus strfile.exe and
		   sc.exe. Caveats:  Concurrent access to meterpreter sessions
		   will cause deployment failure.   Files cannot be downloaded
		   to local machine, they must be downloaded to metasploit box.
		2) Post module deployment: Concurrent access to meterpreter
		   sessions works fine. Requires post module installed in
		   metasploit, as well as standard deployment files. It does not
		   however require strfile.exe or sc.exe.
