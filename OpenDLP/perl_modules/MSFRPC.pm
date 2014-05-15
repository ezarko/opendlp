#This file was modified from the Net::MSFRPC - Metasploit MSG-RPC Communications Module Version 0.01.

package Net::MSFRPC;

use warnings;
use strict;
require Data::MessagePack;
require LWP;
require HTTP::Request;

=head1 NAME

N2Net Security Inc custom impelemtation of Net::MSFRPC.

=head1 VERSION

Version: N2NetSec1.0

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

This module facilitates MSG-RPC communication with metasploit.

	use strict;
	require MSFRPC;
	use Data::Dumper;

	my ($cli, $ret);

	# Create a new Net::MSFRPC instance
	$cli = new Net::MSFRPC(());

	# Login to Metasploit
	$cli->login('msf','abc123');

	# Get MSF version information
	$ret = $cli->call('core.version');
	
	# Print the resulting data structure to the screen
	print Dumper($ret);


=head1 SUBROUTINES/METHODS

=head2 new

Create a new Net::MSFRPC object. Takes an optional hash as an argument.This hash
can contain any or all of the following values:
	
	
	_uri    : The url to connect to (Default: '/api/')
	_host   : The host to connect to (Default: '127.0.0.1')
	_port   : The Remote port to connect to (Default: 55552)
	_ssl    : Use SSL (Default: 0 [DISABLED])
	_timeout: Timeout for HTTP requests (Default: 30 seconds)


=cut


sub new {
	my $class = shift;
	my %opts = @_;

	my $self = {
		_uri => '/api/',
		_host => '127.0.0.1',
		_port => 55552,
		_ssl => 0,
		_client => undef,
		_authenticated => 0,
		_token => undef,
		_url => undef,
		_mp => Data::MessagePack->new(),
		_timeout => 30,
		_error => undef
	};
	foreach my $k (keys %opts)
	{
		$self->{$k} = $opts{$k};
	}
	my $to = $self->{_timeout};	
	$self->{_client} = LWP::UserAgent->new;
	$self->{_client}->timeout($to);
	$self->{_url} = ($self->{_ssl} ? "https" : "http") . "://" . $self->{_host} . ":" . $self->{_port} . $self->{_uri};
	bless $self, $class;
	return $self;
	
}

=head2 call

Call a method on the MSF server.  Allows for two options, the first being
required and is the method.  An optional array is available for additional 
options or hashes. Returns the unpacked response if successful, undef 
otherwise. If unsuccessful, use the getError() method to retrieve the
error message.

=cut


sub call{
	my $self = shift;
	my $meth = shift;
	my @opts = @_;
	$self->{_error} = undef; #reset this before attempting a new action
	
	if($meth ne 'auth.login' and !$self->{_authenticated}){
		$self->{_error} = "MSFRPC: Not Authenticated";
		return undef;
	}elsif ($meth ne 'auth.login') {
		unshift @opts,$self->{_token};
	}
	unshift @opts, $meth;
		
	my $req = new HTTP::Request('POST',$self->{_url});
	$req->content_type('binary/message-pack');

	$req->content($self->{_mp}->pack(\@opts));
	my $res = $self->{_client}->request($req);
	if ($res->code == 500) {
    $self->{_error} = "MSFRPC: Could not connect to " . $self->{_url};
    return undef;
	}
	if ($res->code == 501 && lc($res->header("client_warning")) eq "internal response" &&  index($res->message, "Protocol scheme \'https\' is not supported") != -1) {
	  $self->{_error} = "MSFRPC: There is no SSL perl module available to make this request. Internal response: " . $res->message;
	  return undef;
	} 
	if ($res->code != 200) {
	  $self->{_error} = "MSFRPC: Request failed for method '$meth'. HTTP Error: " . $res->code . " - " . $res->message;
	  return undef;
	}

	return  $self->{_mp}->unpack($res->content);
	
}

=head2 login

Login to the MSF server.  Takes two arguments, the username and password for
authentication.

=cut

sub login {
	my $self = shift;
	my $user = shift;
	my $pass = shift;

  $self->{_error} = undef; #reset this before attempting a new action
	
	my $ret = $self->call('auth.login',$user,$pass);

	if ($ret->{'result'} && $ret->{'result'} eq 'success') {
		$self->{_token} = $ret->{'token'};
		$self->{_authenticated}  = 1;
		return 0;
	} else{
	  if (!($self->{_error})) {
	    $self->{_error} =  "MSFRPC: Authentication Failure";
	  }
	  return -1;
	}
}

=head2 getError

Returns an error message indicating the reason for failure (or undef if 
no error occurred).

=cut

sub getError {
  my $self = shift;
  return $self->{_error};
}

sub getToken {
  my $self = shift;
  return $self->{_token};  
}

sub getAuthenticated {
  my $self = shift;
  return $self->{_authenticated};
}

sub updateToken {
  my $self = shift;
  $self->{_token} = shift;
  return 0;
}

sub setTimeout { 
  my $self = shift;
  my $to = shift;
  $self->{_timeout} = $to;
  $self->{_client}->timeout($to);
  return 0;
}

sub getTimeout {
  my $self = shift;
  return $self->{_timeout};
}
  
=head1 AUTHOR

Ryan Linn, C<< <rlinn at trustwave.com> >>

=head1 MODIFIED BY

Charles E. Smith, N2 Net Security, Inc.
(Added timeout support, replaced die with error handling more suitable
for use in OO modules).

=head1 SUPPORT

You can find documentation for this module with the perldoc command.

    perldoc MSFRPC


=head1 ACKNOWLEDGEMENTS

Thanks to all of the Metasploit team, especialy HDM, Egypt, JCran, and Jduck.
Additional thanks go to Steve Ocepek and the rest of Trustwave SpiderLabs


=head1 LICENSE AND COPYRIGHT

Copyright (C) 2011 Trustwave
http://www.trustwave.com

Modifications by Charles Smith, N2 Net Security, Inc. 2011-2012
http://n2netsec.com

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; version 2 dated June, 1991 or at your option
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

A copy of the GNU General Public License is available in the source tree;
if not, write to the Free Software Foundation, Inc.,
59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


=cut

1; # End of Net::MSFRPC
