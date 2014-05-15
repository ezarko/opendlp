#!/usr/bin/perl
# Copyright (C) 2011-2012 N2 Net Security, Inc.
#
# This file is part of OpenDLP.
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

use strict;
use MetaPostModule;
use Data::Dumper;

my $host = shift;
my $port = shift;
my $user = shift;
my $pass = shift;
my $useSSL = shift;

my $ret_code = 0;

if ($host eq undef || $port eq undef || $user eq undef || $pass eq undef) {
  print "\n*********************************************************************************\n";
  print "* This application tests the connection to the windows/gather/opendlp module    *\n";
  print "* Usage: perl postmodtest.pl [host] [port] [username] [password] [useSSL]       *\n";
  print "* eg   : perl postmodtest.pl 192.168.1.101 55552 msf f00bar!                    *\n";       
  print "*********************************************************************************\n\n";
  exit(-1);
}

my $metaPostModule = MetaPostModule->new();

$metaPostModule->SetLatency(300);
$metaPostModule->SetTimeout(30);

if ($ret_code = $metaPostModule->MetaLogin($host, $port, $user, $pass, $useSSL) ) {
  die($metaPostModule->GetLastError());
}
print "Logged in (Temporary token: " . $metaPostModule->GetAuthToken() . ").\n";
if ($ret_code = $metaPostModule->AcquirePersistentToken()) { 
  die($metaPostModule->GetLastError());
}
print "Acquired persistent token: ". $metaPostModule->GetAuthToken() . ".\n";
print "Current Metasploit Version: " . $metaPostModule->GetMetasploitVersion() . "\n";

if ($ret_code = $metaPostModule->ListSessions()) { 
  die($metaPostModule->GetLastError());
}
my @sessionList = $metaPostModule->GetSessionList();

my $countTo = scalar(@sessionList);
print "Current active sessions: $countTo\n";

if ($countTo > 0) {
  if ($countTo > 10) { 
    print "Displaying first 10 sessions...\n";
    $countTo = 10;
  } else { 
    print "Displaying sessions...\n";
  }  
  
  for (my $i = 0; $i < $countTo; $i++) {     
    print "  Session " . $sessionList[$i]->sessionName .": ";
    print $sessionList[$i]->target_host  . " - " . $sessionList[$i]->info . "\n";        
  }
} 
print "Checking for OpenDLP post module...";
$metaPostModule->SetModuleName("windows/gather/opendlp");
if ($ret_code = $metaPostModule->CheckForModule()) {
  die($metaPostModule->GetLastError());
} else { print "Found post module.\n"; }

if ($ret_code = $metaPostModule->ReleasePersistentToken()) { 
  die($metaPostModule->GetLastError());
}
print "Released persistent token.\n";   
print "Done.\n\n";

