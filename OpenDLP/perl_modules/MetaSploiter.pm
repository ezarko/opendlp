#!/usr/bin/perl

# Copyright (c) 2011-2012 N2 Net Security, Inc.
#
# MetaSploiter is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version.
# 
# MetaSploiter is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with MetaSploiter.  If not, see <http://www.gnu.org/licenses/>.

# Author: Charles Smith <charles.smith[at]n2netsec.com>

use strict;
use Class::Struct;

package MetaSploiter;

use strict;
use Class::Struct;
use MSFRPC;
use MIME::Base64;
use Time::HiRes qw(usleep nanosleep);
use Data::Dumper;

STDOUT->autoflush(1);

struct 'metaSession' => {
  sessionName => '$',
  target_host => '$',
  type        => '$',
  desc        => '$',
  info        => '$',
  via_exploit => '$',
  via_payload => '$',
  platform    => '$',
  uuid        => '$',  
  tunnel_local => '$',
  tunnel_peer  => '$',
  #don't care about these
  #workspace    => '$',
  #username     => '$',
  #exploit_uuid => '$',
  #routes       => '$',   
};

our $x = undef;
sub new {
  my $class = shift;  #name of the class. MetaSploiter
  my $self = { #member variables stored here
    _ResponseHash => undef,
    _LoginResult => "",
    _ErrorCode => "",
    _ErrorString => "",
    _ErrorClass => "",
    _CommandResponse => "",
    _DebugTrace => 0,
    _Latency => 100, #milliseconds
    _LastError => "",
    _Logging => 0,
    _Busy => 0,
    _Timeout => 30, #seconds    
    _SessionList => undef,
    _Client => undef,
    _MerterpreterMode => 0 # 0 for meterpreter_write, 1 for meterpreter_run_single
    
  };
  bless $self, $class;
  return $self;
}
######################################
# define Internal-use helper methods #
######################################
sub __LogMe {
  my $self = shift;
  if (!ref($self)) { return -100; }
  if ($self->GetLogging()) {
    print $_[0] . "\n";
  }
}

sub ClearResponse {
  my $self = shift;
  if (!ref($self)) { return -100; }
  undef($self->{_ResponseHash});
  
  $self->{_LoginResult    } = "";
  $self->{_ErrorCode      } = "";
  $self->{_ErrorString    } = "";
  $self->{_CommandResponse} = "";
  $self->{_LastError      } = "";
  return 0;
}

sub __ParseError { #First step in parsing any response.
  my $self = shift;
  if (!ref($self)) { return -100; }    
  my $responseHash = $self->GetResponseHash();  
  $self->{_ErrorCode   } = $$responseHash{error_code}; 
  $self->{_ErrorClass  } = $$responseHash{error_class};
  $self->{_ErrorString } = $$responseHash{error_message};
  $self->__SetLastError($$responseHash{error_code} . ": " . $$responseHash{error_message});
  if ($self->{_ErrorString} ne "") { return -1; }
  return 0;
} #sub __ParseError

sub __ParseSessionList{
  my $self = shift;
  if (!ref($self)) { return -100; }  
  undef($self->{_SessionList});
  my @sessionList;
  my $responseHash = $self->GetResponseHash();    
  while (my ($key, $node) = each %$responseHash) {
    
    my $session = metaSession->new(); # Create new storage entry
    
    $session->sessionName  ($key);  #sessionId
    $session->info         ($$node{info});
    #$session->workspace   ($$node{workspace});
    $session->tunnel_peer  ($$node{tunnel_peer});
    $session->uuid         ($$node{uuid});      
    #$session->username    ($$node{username});
    $session->target_host  ($$node{target_host});
    #$session->exploit_uuid($$node{exploit_uuid});
    #$session->routes      ($$node{routes});
    $session->via_exploit  ($$node{via_exploit});
    $session->desc         ($$node{desc});
    $session->via_payload  ($$node{via_payload});
    $session->platform     ($$node{platform});            
    $session->type         ($$node{type});
    $session->tunnel_local ($$node{tunnel_local});
    push @sessionList, $session;
  }
  #print "inside parsessessionlist:\n" . Dumper(@sessionList) . "\n";
  @{$self->{_SessionList}} = @sessionList;
  return 0;
} #sub __ParseSessionList

sub __SetLastError { 
  my $self = shift;
  if (!ref($self)) { return -100; }    
  $self->{_LastError} = shift;
  return 0;
}
sub __RPCCall {  
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention

  undef($self->{_ResponseHash}); 
  my $command = shift;
  my @params = @_;
    
  if ($self->{_Client} == undef) { 
    $self->__SetLastError("RPC Client not initialized. Please login first.");
    return -1;
  }
  if ($self->{_Client}->getAuthenticated() != 1) {
    $self->__SetLastError("Not authenticated. Please login first.");
    return -1;
  }
  if ($self->GetDebugTrace()) { 
    $self->__LogMe("Calling RPC - Command: $command"); 
  }
  $self->{_ResponseHash} = $self->{_Client}->call($command, @params);
  if ($self->{_Client}->getError()) { 
    $self->__SetLastError($self->{_Client}->getError());
    return -1;
  }  
  $self->DoEvents($self->GetLatency());
  if ($self->GetDebugTrace()) { 
    $self->__LogMe("ReceivedData: " . Dumper($self->GetResponseHash())); 
  }
  return $self->__ParseError();  
}

sub DoEvents {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention    
  my $millis = 100;
  if (scalar(@_)) {
    $millis = $_[0];
  }
  if ($millis == 0) { return; }
  usleep($millis * 1000); # 1 millisecond == 1000 microseconds
}
 
sub __ParseCommandResponse() {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention  
  my $responseHash = $self->GetResponseHash();
  $self->{_CommandResponse} = $$responseHash{data};  
  return 0;
} #__ParseCommandResponse

sub __CheckCommandResponse() {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  
  # I don't have anything in the api that says so, but it appears a failed command contains "[-]", and a 
  # successful command contains "[*]". But just in case, I'm going to check for some other keys too.
  # This is a sample failure message:
  # "[-] stdapi_fs_chdir: Operation failed: The system cannot find the file specified."
    # the directory does not exist.
   
  my $commandResponse =  $self->{_CommandResponse};
  if ($commandResponse =~ m/\[\-\]/||  #  m/\[\-\]/  is matching "[-]". 
      $commandResponse =~ m/Operation failed/ ||
      $commandResponse =~ m/Errno/) {
    $self->__SetLastError($commandResponse);
    return -1;
  }
  return 0;
}

sub __ReadChannelResp {
  # Helper method for RemoteExecuteAndReadChannel
  # this method uses the last response to parse out a channel to read from.
  # It reads data from the channel until an error is received. That error will be
  # "[-] No data was returned." most likely, but we don't care really. This is polling
  # for and receiving data from the open channel. If the channel DNE or there is no 
  # output from the channel, simply leave _CommandResponse empty.
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  
  my $sessionName = shift(@_);
  my $ret_code = 0;

  # We'll get an inital response from the meterpreter_write that looks like this:
  # Process 8142 created.
  # Channel 5 created.
  # so parse out '5' out of the string "Channel 5 created"
  
  if ($self->GetCommandResponse() =~  m/Channel/ && $self->GetCommandResponse() =~ m/created/) {
    my @values = split(' ', $self->GetCommandResponse());
    my $pos = 0;
    for ($pos = 0; $pos< scalar(@values); $pos++) {
      if( $values[$pos] eq "Channel") { last; }
    }
    if ( ($pos+1) < scalar(@values)) {
      my $command = "read " . $values[$pos+1];      
      my $completeResp = "";
      while ($ret_code == 0) {
        # Read from channel 2 until we get a  "[-] No data was returned."
        $self->__LogMe ("Read channel: $command");            
        $ret_code = $self->SendAndWait($sessionName, $command);      
        $self->__LogMe($self->GetCommandResponse());  
        if ($ret_code == 0) {
          my $lf = index($self->GetCommandResponse(), "\n");
          if ($lf != -1) {
            my $temp = substr($self->GetCommandResponse(), $lf+2); # "Read 4177 bytes from 5\n\n[data]\n"
            $temp =~ s/\r\r/\r/g; # for some reason getting \r\r\n in the console output. I think either perl or metasploit is translating \n to \r\n without checking if it's already \r\n.
            if ($temp =~ m/\r\n$/) { $temp = substr($temp, 0, -2); } 
            elsif ($temp =~ m/\n$/) { $temp = substr($temp, 0, -1); }
            $completeResp .= $temp;        
          } else {
            $completeResp .= $self->GetCommandResponse();  
          }        
        }
      }
      $self->__SetLastError(""); # error from last can be ignored.
      $self->{_CommandResponse} = $completeResp;
      return 0;
    }  
  }
  return 0; # should I error here if I can't parse a channel out?
} #__ReadChannelResp

sub CheckForArmitage {
  #returns -1 for error
  #returns 0 if there is no armitage integratio with metasploit
  #returns 1 if this is an armitage console
  
  #A test to determine if Armitage is connected to MFSRPC is:
  #1 - Connect to MSFRPC
  #2 - issue a console.create and store the id
  #3 - issue a console.read with the stored id, this gets the banner of the console
  #4 - issue a console.write with the stored id and "set ARMITAGE_SERVER\n"
  #5 - issue a console.read with the stored id, and run a regex like (.*?):(.*?)/(.*?)\n.*) to determine if the server was set. The possibilities of output are:
  #- "[-] Unknown variable\nUsage: set [option] [value]\n\nSet the given option to value. If value is omitted, print the current value.\nIf both are omitted, print options that are currently set.\n\nIf run from a module context, this will set the value in the module's\ndatastore. Use -g to operate on the global datastore\n\n"

  #OR
  #- "ARMITAGE_SERVER => 10.211.55.10:55553/somehashvalue\n"
  #6 - issue a console.session_kill with the stored id
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention

  $self->ClearResponse();
  $self->__LogMe("Checking for Armitage.");  
  if ($self->__RPCCall("console.create")) { return -1; }  
  my $consoleId = $self->GetResponseHash()->{id}; #$responseHash->{id};
  
  # Read the banner and everything from the console.
  $self->ClearResponse();  
  if ($self->__RPCCall("console.read", $consoleId) ) { return -1; }  
      
  # If this works, we've connected to an armitage instance.
  $self->ClearResponse();
  if ($self->__RPCCall("console.write", $consoleId, "set ARMITAGE_SERVER\n") ) {  return -1;};
  
  #Wait loop
  my $ret_code = 0;
  $self->{_Busy} = 1;
  $self->ClearResponse();
  my $start = time();  
  while (length($self->GetCommandResponse()) == 0) {
    $self->DoEvents($self->GetLatency());    
    if ($ret_code = $self->__RPCCall("console.read", $consoleId)) { goto FIN; }
    if ($ret_code = $self->__ParseCommandResponse()) { goto FIN; }
    
    my $currTime = time();      
    if ($currTime > ($start + $self->GetTimeout())) {
      $self->{_Busy} = 0;
      $self->__SetLastError("Timeout.");
      return -2;
    }
  } 
FIN:  
  $self->{_Busy} = 0;
  if ($ret_code) { return $ret_code; }
  #end wait loop

  # From what I understand, I have to poll a console just like meterpreter
  # which means on a slow machine or a slow connection this may not
  # complete in only one iteration, which is why I have the wait loop above.
  
  
  my $ret_code = $self->__CheckCommandResponse();
  
  my $armitage = 0;
  if ($ret_code == 0) {        
    $armitage = 1;
  } else {
    $self->ClearResponse();
    if ($self->__RPCCall("console.write", $consoleId, "set ARMITAGE_USER\n") ) {  return -1;};
    
    
    #Wait loop
    my $ret_code = 0;
    $self->{_Busy} = 1;
    $self->ClearResponse();
    my $start = time();  
    while (length($self->GetCommandResponse()) == 0) {
      $self->DoEvents($self->GetLatency());    
      if ($ret_code = $self->__RPCCall("console.read", $consoleId)) { goto FIN2; }
      if ($ret_code = $self->__ParseCommandResponse()) { goto FIN2; }
      
      my $currTime = time();      
      if ($currTime > ($start + $self->GetTimeout())) {
        $self->{_Busy} = 0;
        $self->__SetLastError("Timeout.");
        return -2;
      }
    } 
  FIN2:  
    $self->{_Busy} = 0;
    if ($ret_code) { return $ret_code; }
    #end wait loop
  
    $ret_code = $self->__CheckCommandResponse();
    if ($ret_code == 0) { $armitage = 1; }
  }
  
  $self->ClearResponse();
  $self->__LogMe("Destroying console.");
  if ($self->__RPCCall("console.destroy", $consoleId) )  { return -1; }  
  my $result = $self->GetResponseHash()->{result};
  if (!$result || $result ne "success") { 
    $self->__SetLastError("Unable to delete console $consoleId. Server returned result=$result");
    return -1; 
  }
  
  return $armitage;
}

##########################
# define Exposed methods #
##########################

sub MetaLogin {

  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention

  my $host = shift(@_);  
  my $port = shift(@_); # default should be 55552
  my $user = shift(@_);
  my $pass = shift(@_);
  my $useSSL = shift(@_);
  my $ret_code = 0;
  
  undef($self->{_Client});   
  $self->ClearResponse();
    
  if (!$host || $host eq "") {
    $self->__SetLastError("MetaLogin: host parameter must have a value.");
    return -1;
  }
  if ($port == 0) {
    $self->__SetLastError("MetaLogin: port parameter must have a value.");
    return -1;
  }
 
  $self->{_Client} = Net::MSFRPC->new(
    _host=>$host,
    _port=>$port,
    _timeout=>$self->GetTimeout(),
    _ssl=>$useSSL
  );
  
  $self->__LogMe("Initialized RPC Client.");  
  
  $self->__LogMe("Logging in user \"$user\".");  
  $ret_code = $self->{_Client}->login($user, $pass);
  if ($ret_code || $self->{_Client}->getError()) {
    $self->__SetLastError($self->{_Client}->getError());
    $self->__LogMe($self->GetLastError());
    return $ret_code;
  }
  
  if ($ret_code = $self->__ParseError()) { return $ret_code; }  
  return 0;  
} #MetaLogin

sub GetMetasploitVersion {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention

  $self->__LogMe("Requesting core.version.");  
  my $ret_code = $self->__RPCCall("core.version");  
  $self->__LogMe(Dumper($self->GetResponseHash()));
  if ($ret_code) { return undef; }  
  
  my $versionString = "";
  $versionString = $self->GetResponseHash()->{version};
  return $versionString;  
}

sub AcquirePersistentToken {

  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  $self->ClearResponse();
  
  my $ret_code = 0;
  $self->__LogMe("Acquiring persistent token.");  
  $ret_code = $self->__RPCCall("auth.token_generate");  
  if ($self->GetResponseHash()->{result} eq "success") {
    $self->{_Client}->updateToken($self->GetResponseHash()->{token});
  } else {
    $self->__SetLastError("Could not acquire persistent token. Server returned: " . $self->GetResponseHash()->{result});
    return -1;
  }
  return $ret_code;
} #AcquirePersistentToken

sub ReleasePersistentToken {
  #Releases the token passed as a parameter.
  #If no token is passed to this method, the current token is released.
  #This will invalidate the session, and should be the last thing you do.
  #Use it as a "DisconnectFromServer". 
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $tok = shift(@_);
  $self->ClearResponse();
  my $ret_code = 0;
  
  if (!$tok) {
    $self->__LogMe("Releasing current token.");  
    $tok = $self->{_Client}->getToken();
  } else {
    $self->__LogMe("Releasing persistent token specified by parameter.");    
  } 
  $ret_code = $self->__RPCCall("auth.token_remove", $tok);
  if ($ret_code) { return $ret_code; }
  if ($self->GetResponseHash()->{result} ne "success") {
    $self->__SetLastError($self->GetResponseHash()->{result});
    return -1;
  }
  return 0;
} 
  
#Not sure, but I believe console commands are blocking, because I've never had a session list returned
#truncated or not at all. Same with login. But meterpreter commands are different, you have to poll
#the console to see if there's been any data recently.

sub ListSessions {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  $self->ClearResponse();
  $self->__LogMe("Requesting session list.");
  if ($self->__RPCCall("session.list") )  { return -1; }
  return $self->__ParseSessionList();
} #MetaListSessions

sub ReadFile {
  # note, this will only return the first bit of the file. if it's a big file
  # continue to receive with MeterpreterRead. Unfortunately, there is no way
  # to determine when the transmission is done, save receiving a bunch of 
  # zero-length responses. (Just one won't do, because often there's 
  # network lag or metasploit just being slow, and a zero-length response will
  # be received randomly in between data responses.)
  # This method has limited use for small files. It's a better idea to use
  # DownloadFile().
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $session = shift;
  my $filename = shift;  
  $filename =~ s/\\/\//g; # replaces backslash with forward slash  
  $self->__LogMe("Retrieve File Contents of '$filename'.");
  return $self->SendMeterpreterWrite($session, "cat \"$filename\"");
}

sub UploadFile {
  # returns 0 for success.
  # returns -1 for failure.
  # returns -2 for timeout.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $session = shift;
  my $filename = shift;
  $self->__LogMe("Uploading File $filename.");
  return $self->SendAndWait($session, "upload \"$filename\"", "[*] uploaded");  
} # UploadFile

sub DownloadFile {
  # returns 0 for success.
  # returns -1 for failure.
  # returns -2 for timeout.
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $session  = shift;
  my $filename = shift;
  my $destpath = shift;
  $filename =~ s/\\/\//g; # replaces backslash with forward slash
  $destpath =~ s/\\/\//g; # replaces backslash with forward slash
  if (length($destpath) > 0) { $self->__LogMe("Downloading File '$filename' to '$destpath'."); }
  else { $self->__LogMe("Downloading File '$filename'."); }
  
  # Expected _CommandResponses:
  # Success:
  # [*] downloading: file.txt -> file.txt
  # [*] downloaded : file.txt -> file.txt
  #
  # Failure:
  # [-] stdapi_fs_stat: Operation failed: The system cannot find the file specified.
  if (length($destpath) > 0) {
    return $self->SendAndWait($session, "download \"$filename\" \"$destpath\"", "[*] downloaded");
  } else {
    return $self->SendAndWait($session, "download \"$filename\"", "[*] downloaded"); # so we wait for it to complete.
  }
} # DownloadFile

sub SendMeterpreterWrite {
  # this DOES NOT WAIT FOR A RESPONSE
  # it does attempt to retrieve a response, but the console may not have a response waiting for you yet.
  # you must continue to poll with MeterpreterRead() if you are expecting response data.
  # Or preferredly, use the SendAndWait method instead.
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  my $session     = shift;
  my $command     = shift;
  $command .= "\n";  #terminate command with newline.
  my $ret_code = 0;
  
  my $meterpreter_mode = "session.meterpreter_write";
  if ($self->{_MeterpreterMode} == 1) {
    $meterpreter_mode = "session.meterpreter_run_single";
  }
  
  undef($self->{_ResponseHash});
  $self->{_CommandResponse} = "";  
  #if ($ret_code = $self->__RPCCall("session.meterpreter_write", $session, $command);  { return $ret_code; }
  if ($ret_code = $self->__RPCCall($meterpreter_mode, $session, $command) )  { return $ret_code; }  
  undef($self->{_ResponseHash});
  if ($ret_code = $self->__RPCCall("session.meterpreter_read", $session)) { return $ret_code; }
  if ($ret_code = $self->__ParseCommandResponse()) { return $ret_code; }  
  # if you get the response here great, but chances are you still need to poll with MeterpreterRead.
  return $self->__CheckCommandResponse();
} # SendMeterpreterWrite

sub SendAndWait {

  # sends data and waits for a response. If no timeout is received in _Timeout 
  # seconds, the method will fail with a timeout (-2) error.
  # This method only works if you're expecting a response to your command. A 
  # cd "c:\Program Files" does not return a response. pwd, however, does return
  # data in response. (hint: That's how I make sure directories are changed properly).
  # This will greatly help speed things up. Now latency is merely the num of 
  # milliseconds you spin in a DoEvents loop, and should probably not be changed by
  # anyone.
  
  # returns 0 for success.
  # returns -1 for failure.
  # returns -2 for timeout.
  
  #session: Session Id
  #command: Command to execute
  #until  : wait until this string is received. If blank, will return as soon as any data is received.
  
  # Note, any response received that starts with [-], or any fault parsed from the xml, will 
  # break out of the wait loop and return -1.
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  my $session     = shift;
  my $command     = shift;
  my $until       = shift;
  $command .= "\n";  #terminate command with newline.
  my $ret_code = 0;
  
  if ($self->{_Busy}) { 
    $self->__SetLastError("Busy performing current action.");
    return -1;
  }  
  $self->{_Busy} = 1;
    
  my $meterpreter_mode = "session.meterpreter_write";
  if ($self->{_MeterpreterMode} == 1) {
    $meterpreter_mode = "session.meterpreter_run_single";
  }
    
  undef($self->{_ResponseHash});
  $self->{_CommandResponse} = "";
  if ($ret_code = $self->__RPCCall($meterpreter_mode, $session, $command))  { goto DONE; }
  undef($self->{_ResponseHash});
      
  my $start = time();
  if (length($until) == 0) {
    while (length($self->GetCommandResponse()) == 0) {
      $self->DoEvents($self->GetLatency());    
      if ($ret_code = $self->MeterpreterRead($session) ) { goto DONE; }
      
      my $currTime = time();      
      if ($currTime > ($start + $self->GetTimeout())) {
        $self->{_Busy} = 0;
        $self->__SetLastError("Timeout.");
        return -2;
      }
    }  
  } else {  # $until contains a search string. Loop until that string is matched (or timeout).
    while (index(lc($self->GetCommandResponse()), lc($until)) == -1) {
      $self->DoEvents($self->GetLatency());    
      if ($ret_code = $self->MeterpreterRead($session) ) { goto DONE; }
      
      my $currTime = time();      
      if ($currTime > ($start + $self->GetTimeout())) {
        $self->{_Busy} = 0;
        $self->__SetLastError("Timeout.");
        return -2;
      }
    }
   }
DONE:  
  $self->{_Busy} = 0;
  if ($ret_code) { return $ret_code; }
  return $self->__CheckCommandResponse();  
} # SendAndWait

sub MeterpreterRead {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
   
  my $session  = shift;
  my $ret_code = 0;
  
  if ($ret_code = $self->__RPCCall("session.meterpreter_read", $session)) { return $ret_code; }
  if ($ret_code = $self->__ParseCommandResponse()) { return $ret_code; }  
  return $self->__CheckCommandResponse();
} #MeterpreterRead

sub ChangeLocalPath {
  # returns 0 for success.
  # returns -1 for failure.
  # returns -2 for timeout.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $sessionId = shift;
  my $path      = shift;
  if ($sessionId eq "") { $self->__SetLastError("You must specify the sessionId parameter."); return -1; }
  if ($path      eq "") { $self->__SetLastError("You must specify a path to change to.");     return -1; }  
  $self->ClearResponse();
  $path =~ s/\\/\//g; # replaces backslash with forward slash
  
  if ($self->{_Busy}) { 
    $self->__SetLastError("Busy performing current action.");
    return -1;
  }  
  if ($self->SendMeterpreterWrite($sessionId, "lcd \"$path\"")) { return -1; }
  # This ensures the command is completed and puts the current local path in _CommandResponse.
  return $self->SendAndWait($sessionId, "lpwd");
} # ChangeLocalPath

sub ChangeRemotePath {
  # returns 0 for success.
  # returns -1 for failure.
  # returns -2 for timeout.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  my $sessionId = shift;
  my $path = shift;
  if ($self->{_Busy}) { 
    $self->__SetLastError("Busy performing current action.");
    return -1;
  }  
  if ($sessionId  eq "") { $self->__SetLastError("You must specify the sessionId parameter."); return -1; }
  if ($path       eq "") { $self->__SetLastError("You must specify a path to change to.");     return -1; }
  $self->ClearResponse();
  
  $path =~ s/\\/\//g; # replaces backslash (\) with forward slash (/).   
  if ($self->SendMeterpreterWrite($sessionId, "cd \"$path\"")) {
    $self->__SetLastError("No such directory.  (" . $self->GetCommandResponse() . ")");
    return -1;
  } 
  # This ensures the command is completed and puts the current path in _CommandResponse.
  return $self->SendAndWait($sessionId, "pwd");   
} # ChangeRemotePath

sub CreateRemotePath {
 # Problem: command "cd /dirname". When the command succeeds, there is an empty result. When it fails,
 #   there's an error string "[-] stdapi_fs_chdir: Operation failed". Or there should be. The problem
 #   is this: When I send a meterpreter_write, the response I get back is always "ok, request received".
 #   I then do a meterpreter_read to get the response back from the system. There may or may not be
 #   a response waiting for me yet. If there's not, I can continue polling for a certain amount of time 
 #   (using _Latency)... or I can issue a pwd command. pwd always returns a response, and I can poll
 #   for it and expect to receive it. Then I can even use the data returned to verify that the path 
 #   has indeed changed.

  # returns 0 for success.
  # returns 1 for success with warning.
  # returns -1 for failure.
  # returns -2 for timeout.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $sessionId = shift;
  my $destPath = shift; #no filename!
  my $ret_code = 0;  
  if ($sessionId eq "") { $self->__SetLastError("You must specify the sessionId parameter."); return -1; }
  if ($destPath eq "")  { $self->__SetLastError("You must specify a path to create.");        return -1; }
  if ($self->{_Busy}) { 
    $self->__SetLastError("Busy performing current action.");
    return -1;
  }  
  $self->ClearResponse();
  $self->__LogMe("CreateRemotePath: $destPath");
  # Break the destination path up into individual directories, splitting on the slash.
  $destPath =~ s/\\/\//g; # replaces backslash (\) with forward slash (/).   
  my @destArray = split(/\//, $destPath);  #splits path on the forward slash.

  my $lastPath = "";
  if ($destArray[0] =~ /:$/) { #ends with a colon.
    my $cmd = "cd " . $destArray[0];  # cd c: works. 
    $self->__LogMe($cmd);
    if ($self->SendMeterpreterWrite($sessionId, $cmd) ) { $self->__SetLastError("No such drive. (command: $cmd). (" . $self->GetCommandResponse() . ")"); return -1; }    
    if ($self->SendAndWait($sessionId, "pwd")) { return -1; }       
    if (index(lc($self->GetCommandResponse()), lc($destArray[0])) != 0) {  #this is not a bug, !=0 is correct.
      $self->__SetLastError("No such drive. (command: $cmd). (" . $self->GetCommandResponse() . ")"); 
      return -1; 
    }
    $lastPath = lc($self->GetCommandResponse());
    chomp($lastPath);
    $destArray[0] = "\/"; # next command will be "cd /"

  } elsif ($destArray[0] eq "") { $destArray[0] = "\/"; }
   
  # cd as far into as you can before you find a nonexistent directory
  while(scalar(@destArray)) {   
    if ($destArray[0] eq "") { last; } # break out of loop if encounter empty
    my $cmd = "cd \"" . $destArray[0] . "\"";    
    $self->__LogMe($cmd);
    $ret_code = $self->SendMeterpreterWrite($sessionId, $cmd); 
    if ($ret_code) { last; } #previous cd command failed, so break out of the loop and create the rest of the path with mkdir";
        
    #no guarantee that we received the error to a cd into a bad directory.
    #so get the pwd and check it.
    $self->__LogMe("pwd");
    if ($self->SendAndWait($sessionId, "pwd")) { last; }  #this may pick up a response to a failed CD command if latency is low or the target machine is slow. That's perfectly okay.
    my $commandResponse = $self->GetCommandResponse();
    chomp($commandResponse);
    $self->__LogMe($commandResponse);
     
    # The root directory is special.
    
    if ($destArray[0] eq "\/") {      
      #if (!(commandResponse.EndsWith('\') || commandResponse.EndsWith('/')) {
      if (!(index($commandResponse, "\\") == (length($commandResponse) - 1)) ||
         (index($commandResponse, "/") == (length($commandResponse) - 1)) ) {
        $self->__SetLastError("Cannot change to root directory."); 
        return -1;
      }
    } else {        
      #if the last pwd was "c:\crazy" and $destArray[0] contains "Train", 
      #check the current response for the text "train", starting at the length
      #of the last pwd.
      if (index(lc($commandResponse), lc($destArray[0]), length($lastPath)) == -1) { 
        # We were unable to cd into this path, so break out of the loop.
        $lastPath = $commandResponse;     
        last; 
      }
    }
    $lastPath = $commandResponse;     
    shift (@destArray);  # otherwise remove the directory from the list and continue
  } 
  # if there are no directories left in the list to create, it must already exist.
  if (scalar(@destArray) == 0) {
    $self->__SetLastError("Warning: Directory already exists.");
    return 1;
  } 
  
  #now create directories
  while (scalar(@destArray)) {
    if ($destArray[0] eq "") { last; } # break out of loop if encounter empty
    my $cmd = "mkdir \"" . $destArray[0] . "\"";
    $self->__LogMe($cmd);
    if ($ret_code = $self->SendAndWait($sessionId, $cmd)) {
      # If mkdir fails, $_CommandResponse will contain the text :
      # "[-] stdapi_fs_mkdir: Operation failed: The system cannot find the path specified"    
      $self->__SetLastError($self->GetCommandResponse());
      return -1;
    }
    
    $cmd = "cd \"" . $destArray[0] . "\"";    
    $self->__LogMe($cmd);
    if ($ret_code = $self->SendMeterpreterWrite($sessionId, $cmd) ) {
      $self->__SetLastError($self->GetCommandResponse());
      return -1;
    }  
    
    #no guarantee that we received the error to a cd into a bad directory.
    #so get the pwd and check it.
    if ($self->SendAndWait($sessionId, "pwd")) { return -1; }
    my $commandResponse = $self->GetCommandResponse();
    chomp($commandResponse);
      
    #if the last pwd was "c:\crazy" and $destArray[0] contains "Train", 
    #check the pwd response for the text "train",
    if (index(lc($commandResponse), lc($destArray[0]), length($lastPath)) == -1) { 
      $self->SetLastError("Error creating subdirectory " . $destArray[0] . ".");
      return -1;
    }
    shift(@destArray);
  }
  return 0;
} #CreateRemotePath

sub RemoteExecute {
  # Returns immediately, you have no idea of the success or failure of the command.
  # No channel is opened. If the app you run returns console data, the UAC will catch 
  # it and display a warning to the user of the PC. Services are not allowed to interact
  # with the user in windows 7.
  # returns 0 for success.
  # returns -1 for failure.
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  my $sessionId   = shift;
  my $file        = shift;
  my $attributes  = shift;
  
  if ($sessionId eq "") { $self->__SetLastError("You must specify the sessionId parameter."); return -1; }
  if ($file      eq "") { $self->__SetLastError("You must specify a file to execute.");       return -1; }

  my $ret_code = 0;
  #my $command = "execute -f $file";
  my $command = "execute -f \\\"$file\\\"";  
  if ($attributes ne "") { $command .= " -a \"$attributes\""; }    
  $self->__LogMe ("RemoteExecute: $command");
  return $self->SendAndWait($sessionId, $command); 
  # _CommandResponse will contain "Process 4242 created." for success, 
  # or "[-] stdapi_sys_process_execute: Operation failed: blahblah"
} # RemoteExecute

sub RemoteExecuteAndReadChannel {
  # This method executes a file on the remote system, and then 
  # waits for a response. If the file you're executing does not
  # return data to the console, this method will timeout.
  
  # Parameters:
  # $sessionName: name/id that designates the session.
  # $file       : file to execute
  # The remainder of the parameters sent to this method are used as command line arguments for $file.
  
  # command line arguments can NOT contain quotes or backslashes, or this will break.
  # DOS command: 
  #   c:\>file.exe "c:\Program files\OpenDLP" -q -v
  # Metasploit Console command: 
  #   meterpreter > execute -f file.exe -c -a "\"c:/Program files/OpenDLP\" -q -v"
  # Equivalent MetaSploiter command:
  #   RemoteExecuteAndReadChannel("1", "file.exe", "c:/Program files/OpenDLP", "-q", "-v");
  
  # returns 0 for success.
  # returns -1 for failure.
  # returns -2 for timeout.
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  my $sessionName = shift;
  my $file        = shift;
  my $ret_code = 0;
  
  my $command = "execute -f \\\"$file\\\" -c";
  #a single attribute like "\"data16 \\\"configuration file.ini\\\"\"" works.
  if (scalar(@_)) {
    $command .= ' -a "';
    foreach my $attr (@_) {      
      $command .= ' \"' . $attr . '\"';
    }    
    $command .= '"';
  }
  $self->__LogMe ("RemoteExecuteAndReadChannel: $command");   
  if ($ret_code = $self->SendAndWait($sessionName, $command, "Channel") ) { return $ret_code; } #waits for channel info
  return $self->__ReadChannelResp($sessionName);
} # RemoteExecuteAndReadChannel

sub RemoteExecuteAndReadChannelRaw {
  # This works like above, but instead takes a list of arguments.
  # Backslashes and quotation marks are supported. - I think. Needs more testing
  # RemoteExecuteAndReadChannelRaw("1", "file.exe", "outfile.txt -q -v"); 
  # RemoteExecuteAndReadChannelRaw("1", "file.exe", "\"c:\Program Files\outfile.txt\" -q -v");
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  my $sessionName = shift;
  my $file        = shift;
  my $attributes  = shift;
  my $ret_code = 0;
  my $command = "execute -f $file -c";  #-c opens a channel, which we can read from after the transmission.
  if ($attributes ne "") { 
    #$command .= " -a $attributes";    
    
    $attributes =~ s/\\/\\\\/g;  #'\' to '\\'  ("\\" to "\\\\")
    $attributes =~ s/\"/\\\"/g;  #'"' to '\"'  ("\"" to "\\\"")    
    $command .= '-a "' . $attributes . '"';
  }    
  $self->__LogMe ("RemoteExecuteAndReadChannel: $command");   
  if ($ret_code = $self->SendAndWait($sessionName, $command) ) { return $ret_code; }
  return $self->__ReadChannelResp($sessionName);
} #RemoteExecuteAndReadChannelRaw

sub DESTROY { 
#ReleasePersistentToken(); 
}  

####################
# Property Setters #
####################
sub SetDebugTrace { 
  # If DebugTrace is true, the full xml request and response received from the server will be 
  # printed to stdout. Use SetLogging if you want simpler command payload request/responses 
  # printed to stdout. These are separate because turning both on would make for an unreadable
  # mess.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  $self->__SetLastError("");  
  if ($_[0] == 0 || $_[0] == 1) {
    $self->{_DebugTrace} = $_[0];    
  } else {
    $self->__SetLastError("Invalid setting for DebugTrace. Must be 1 or 0.");
    return -1;
  }
  return 0;
} #SetDebugTrace

sub SetLogging {
  # Turns on logging info to help with debugging.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
 
  $self->__SetLastError("");  
  if ($_[0] == 0 || $_[0] == 1) {
    $self->{_Logging} = $_[0]; 
  } else {
    $self->__SetLastError("Invalid setting for Logging. Must be 1 or 0.");
    return -1;
  }
  return 0;
} # SetLogging

sub SetLatency {  #milliseconds
  # Milliseconds to wait in tight DoEvents loops. Increase latency to slow things down, 
  # decrease (to a point) to speed up. If latency is too small, you may consume a lot of cpu.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  $self->__SetLastError("");  
  if ($_[0] eq undef || $_[0] eq "") { $self->{_Latency} = 100; return 0; } 
  if ($_[0] =~ /^\s*[\+\-]?\d+\s*$/ && ($_[0] >= 0)) {
    if ($_[0] < 0) {
      $self->__SetLastError("Latency cannot be negative.");
      return -1;
    }
    $self->{_Latency} = $_[0];
    return 0;
  }  
  $self->__SetLastError("You must specify a positive integer as a parameter to SetLatency.");
  return -1;  
} # SetLatency

sub SetTimeout { #seconds
  # Seconds to wait for a response before giving up and timing out. 
  # In SendAndWait (and all the methods that use it), the control will
  # enter a DoEvents loop and poll the meterpreter server for data. 
  # If the server crashes or loses the response, you don't want to wait
  # forever.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  $self->__SetLastError("");  
  if ($_[0] eq undef || $_[0] eq "") { 
    $self->{_Timeout} = 30; 
    if ($self->{_Client}) { 
      $self->{_Client}->setTimeout(30); 
    }
    return 0; 
  } 
  if ($_[0] =~ /^\s*[\+\-]?\d+\s*$/ && ($_[0] >= 0)) {
    if ($_[0] < 0) { 
      $self->__SetLastError("Timeout cannot be negative.");
      return -1;
    }
    $self->{_Timeout} = $_[0];  #This is the timeout for SendAndWait
    if ($self->{_Client}) { 
      $self->{_Client}->setTimeout($_[0]);       
    }
    return 0;
  }  
  $self->__SetLastError("You must specify a positive integer as a parameter to SetTimeout.");
  return -1; 
} # SetTimeout

####################
# Property Getters #
####################
sub GetCommandResponse  { my $self = shift; return $self->{_CommandResponse}; } # Returns last response payload.
sub GetDebugTrace       { my $self = shift; return $self->{_DebugTrace};      } # Full xml request/responses printed to stdout
sub GetSessionList      { # Contains the session list after a call to ListSessions().
  my $self = shift;   
  if ($self->{_SessionList}) {
    return  @{$self->{_SessionList}};
  }
  return undef;  
} 
sub GetLastError        { my $self = shift; return $self->{_LastError};       } # If a method returned nonzero, this will contain the error message.
sub GetLatency          { my $self = shift; return $self->{_Latency};         } # Milliseconds to wait in tight DoEvents loops.
sub GetTimeout          { my $self = shift; return $self->{_Timeout};         } # Seconds to wait for a response before giving up and timing out. 
sub GetAuthToken        { my $self = shift; return $self->{_Client}->getToken(); }
sub GetResponseHash     { my $self = shift; return $self->{_ResponseHash};    }
sub GetLogging          { my $self = shift; return $self->{_Logging};         }
1;
