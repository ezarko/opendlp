#!/usr/bin/perl

# Copyright (C) 2011-2012 N2 Net Security, Inc.
#
# This file extends OpenDLP.
#
# OpenDLP is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or 
# (at your option) any later version.
# 
# OpenDLP is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with OpenDLP.  If not, see <http://www.gnu.org/licenses/>.
#

package MetaPostModule;

use strict;
use Class::Struct;
use Data::Dumper;
use MetaSploiter;
our @ISA = qw(MetaSploiter);  

sub new {
    my ($type) = @_;    
    my $self = $type->SUPER::new();
    
    $self->{_SourcePath   } = "";
    $self->{_RemotePath   } = "";
    $self->{_ConfigString } = "";
    $self->{_SessionId    } = "";
    $self->{_CommandLog   } = "";
    $self->{_ModuleName   } = "";
    $self->{_Verbose      } = "0";
    $self->{_FileToRead   } = "";
    $self->{_FileData     } = undef;
    bless $self, $type;
    return $self;
}
  
###################
# Exposed Methods #
###################
sub DeployOpenDLP {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  return $self->__OpenDLPService("DEPLOY");
}
sub StopOpenDLP{
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  return $self->__OpenDLPService("STOP");
}
sub StartOpenDLP{
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  return $self->__OpenDLPService("START");
}
sub DeleteOpenDLP{
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  return $self->__OpenDLPService("DELETE");
}
sub RemoveRemotePath{
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  return $self->__OpenDLPService("REMOVE");
}
sub ReadFile {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
    
  my $file = shift;
  if (!$file || $file eq "") {
    $self->__SetLastError("No file specified for reading.");
    return -1;
  }
  
  $self->{_FileToRead} = $file;
  my $ret_code = $self->__OpenDLPService("READFILE");
  if ($ret_code) { return $ret_code; }
  
  my $resp = $self->GetCommandResponse();  
  my $startIndex = index($resp, "[***BEGIN FILE DATA***]");
  my $endIndex   = rindex($resp, "[***END FILE DATA***]");
  
  if ($startIndex == -1 || $endIndex == -1) {
    $self->__SetLastError("Error parsing file data.");
    return -1;
  }    
  $startIndex += length("[***BEGIN FILE DATA***]");  
  if ($startIndex >= $endIndex) {
    $self->__SetLastError("Error parsing file data.");
    return -1;
  }
  my $dataLen = $endIndex - $startIndex;
  my $fileData = substr($resp, $startIndex, $dataLen);
  $self->{_FileData} = $fileData;
  return 0;
}
sub TestMe {
  my $self = shift;
  my $modName = $self->GetModuleName();
  if (!$modName || $modName eq "") { 
    $self->__SetLastError("You must set ModuleName first before calling this method.");
    return -1;
  }  
  return $self->__OpenDLPService("TEST");
}

sub CheckForModule {
  
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  
  my $modName = $self->GetModuleName();
  if (!$modName || $modName eq "") {  
    $self->__SetLastError("You must set ModuleName first before calling this method.");
    return -1;
  }
  $self->ClearResponse();
  my $ret_code = 0;  
  if ($ret_code = $self->__RPCCall("module.post")) { return $ret_code; }      
  my $responseHash = $self->GetResponseHash();
  my @modules = @{$$responseHash{modules}};
    
  my $i = $self->__ArrayIndexOf($modName, @modules );
  if ($i == -1) { 
    $self->__SetLastError("Module $modName not found on Metasploit.");
    return -1;
  }
  return 0;
  
}

sub GetModuleOptions {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention  
  my $modName = $self->GetModuleName();
  if (!$modName || $modName eq "") { 
    $self->__SetLastError("You must set ModuleName first before calling this method.");
    return -1;
  }
  $self->ClearResponse();
  my $ret_code = 0;  
  if ($ret_code = $self->__RPCCall("module.options", "post", $modName)) { return $ret_code; }      
  #my $responseHash = $self->GetResponseHash();
  #print Dumper($responseHash);
  return 0;
}
sub ClearResponse {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention  
  undef($self->{_FileData});
  return $self->SUPER::ClearResponse();
}
  
###################
# Helper Methods  #
###################
sub __ArrayIndexOf{
  #first param = string to search for.
  #second param = array to search in.  
  my $type = $_[0];    
  if (ref($type)) { shift; }
  for(1..@_){$_[0]eq$_[$_]&&return$_-1}-1
}

sub __ReadConsoleAndWait {
  # Reads from the console, only returns when console is no longer busy.
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  
  my $consoleId = shift;
  $self->ClearResponse();
  
  my $ret_code = 0;
  my $consoleBusy = 0;
  do {
    if ($ret_code = $self->__RPCCall("console.read", $consoleId) ) { return $ret_code; }
    $consoleBusy = $self->GetResponseHash()->{busy};
    $self->{_CommandResponse} .= $self->GetResponseHash->{data};
    $self->{_CommandLog} .= $self->GetResponseHash->{data};
  } while ($consoleBusy);
  #my $prompt = $self->GetResponseHash()->{prompt};
  return 0;  
}

sub __SendConsoleCommand {

  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  
  my $consoleId = shift;
  my $command   = shift;
  $command .= "\n";  #terminate command with newline.
  my $ret_code = 0;
  $self->ClearResponse();
  $self->{_CommandLog} .= ">>$command";
  if ($ret_code = $self->__RPCCall("console.write", $consoleId, $command) ) { return $ret_code; }
  if ($ret_code = $self->__ReadConsoleAndWait($consoleId) ) { return $ret_code; }
  return $self->__CheckCommandResponse();
}

sub __CheckCommandResponse {
  my $self = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  my $ret_code = $self->SUPER::__CheckCommandResponse();
  
  my $lastErr = $self->GetLastError();
  my $start = index($lastErr, "[-]");
  if ($start == -1) { return $ret_code;}
  $lastErr = substr($lastErr, $start);
  my $end   = index($lastErr, "\n");
  if ($end != -1) {
    $lastErr = substr($lastErr, 0, $end);
  }
  $self->__SetLastError($lastErr);
  return $ret_code;
}
sub __SetupModule {
  my $self = shift;
  my $consoleId = shift;
  my $action = shift;
  my $ret_code = 0;
  
  if (!ref($self)) { return -100; } # invalid calling convention    
  my $modName = $self->GetModuleName();
  if (!$modName || $modName eq "") { 
    $self->__SetLastError("You must set ModuleName first before calling this method.");
    return -1;
  }


  my $sessionId    = $self->GetSessionId(); 
  my $remotePath   = $self->GetRemotePath();  
  my $sourcePath   = $self->GetSourcePath();  
  my $configString = $self->GetConfigString();
  my $verbose      = $self->GetVerbose();    
  my $fileToRead   = $self->{_FileToRead};
 
  $self->ClearResponse();
  if ($ret_code = $self->__ReadConsoleAndWait($consoleId) ) { return $ret_code; } # read the banner and discard
  $self->{_CommandLog} = "";
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "use $modName") ) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set ACTION $action")) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set SESSION '$sessionId'"         )) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set REMOTE_PATH '$remotePath'"    )) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set SOURCE_PATH '$sourcePath'"    )) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set CONFIG_STRING '$configString'")) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set VERBOSE '$verbose'"           )) { return $ret_code; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "set FILE_TO_READ '$fileToRead'"   )) { return $ret_code; }
  return 0;
}
sub __OpenDLPService {
  my $self = shift;
  my $action = shift;
  if (!ref($self)) { return -100; } # invalid calling convention
  if (!$action || $action eq "") { 
    $self->__SetLastError("Action required.");
    return -1;
  }
  
  my $modName = $self->GetModuleName();
  if (!$modName || $modName eq "") { 
    $self->__SetLastError("You must set ModuleName first before calling this method.");
    return -1;
  }

  my $ret_code = 0;
  $self->ClearResponse();
  if ($ret_code = $self->__RPCCall("console.create") ) { return $ret_code; }
  my $consoleId = $self->GetResponseHash->{id};
  if ($ret_code = $self->__SetupModule($consoleId, $action) ) { goto DONE; }
  if ($ret_code = $self->__SendConsoleCommand($consoleId, "run")) { goto DONE; }
  
DONE:
  my $lastError = $self->GetLastError();
  $self->__RPCCall("console.destroy", $consoleId);
  $self->__SetLastError($lastError);
  return $ret_code;
}
###################
# Getters/Setters #
###################

sub GetCommandLog  { my $self = shift; return $self->{_CommandLog};   } #readonly
sub GetSourcePath  { my $self = shift; return $self->{_SourcePath};   }
sub GetRemotePath  { my $self = shift; return $self->{_RemotePath};   }
sub GetConfigString{ my $self = shift; return $self->{_ConfigString}; }
sub GetSessionId   { my $self = shift; return $self->{_SessionId};    }
sub GetModuleName  { my $self = shift; return $self->{_ModuleName};   }
sub GetVerbose     { my $self = shift; return $self->{_Verbose};      }
sub GetFileData    { my $self = shift; return $self->{_FileData};     }

sub SetModuleName {
  my $self = shift;
  $self->{_ModuleName} = shift;
  return 0;
}
sub SetSourcePath {
  my $self = shift;
  $self->{_SourcePath} = shift;
  return 0;
}
sub SetRemotePath {
  my $self = shift;
  $self->{_RemotePath} = shift;
  return 0;
}
sub SetConfigString{
  my $self = shift;
  $self->{_ConfigString} = shift;
  return 0;
}
sub SetSessionId{
  my $self = shift;
  $self->{_SessionId} = shift;
  return 0;
}
sub SetVerbose{
  my $self = shift;
  $self->{_Verbose} = shift;
  return 0;
}
1;

