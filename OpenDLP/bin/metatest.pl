#!/usr/bin/perl
use strict;
use MetaSploiter;

# Copyright (C) 2012 N2 Net Security, Inc. 
# 
# This file is part of MetaSploiter.
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

my $host = shift;
my $port = shift;
my $user = shift;
my $pass = shift;
my $useSSL = shift;

my $ret_code = 0;

if ($host eq undef || $port eq undef || $user eq undef || $pass eq undef) {
  print "\n**************************************************************************\n";
  print "* This application tests the connection to Metasploit                    *\n";
  print "* Usage: perl metatest.pl [host] [port] [username] [password] [useSSL]   *\n";
  print "* eg   : perl metatest.pl 192.168.1.101 55552 msf f00bar!                *\n";       
  print "**************************************************************************\n\n";
  exit(-1);
}

my $metaSploiter = MetaSploiter->new();

$metaSploiter->SetLatency(300);
$metaSploiter->SetTimeout(30);

if ($ret_code = $metaSploiter->MetaLogin($host, $port, $user, $pass, $useSSL) ) {
  die($metaSploiter->GetLastError());
}
print "Logged in (Temporary token: " . $metaSploiter->GetAuthToken() . ").\n";
if ($ret_code = $metaSploiter->AcquirePersistentToken()) { 
  die($metaSploiter->GetLastError());
}
print "Acquired persistent token: ". $metaSploiter->GetAuthToken() . ".\n";
print "Current Metasploit Version: " . $metaSploiter->GetMetasploitVersion() . "\n";

if ($ret_code = $metaSploiter->ListSessions()) { 
  die($metaSploiter->GetLastError());
}
my @sessionList = $metaSploiter->GetSessionList();

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
print "Checking for Armitage... ";
my $arm = $metaSploiter->CheckForArmitage();
if ($arm == -1) { die($metaSploiter->GetLastError()); }
if ($arm == 0) { print "Not using Armitage.\n"; }
if ($arm == 1) { 
  print "WARNING: ARMITAGE DETECTED.\n";
  print "  Armitage and other clients  cannot be used on the same session at the same time. \n";
  print "  When using MetaSploiter, do not interact with \n";
  print "  the session through Armitage, or the client may fail.\n"; 
}

if ($ret_code = $metaSploiter->ReleasePersistentToken()) { 
  die($metaSploiter->GetLastError());
}
print "Released persistent token.\n";   
print "Done.\n\n";

