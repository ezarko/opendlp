#!/usr/bin/perl

# Copyright Andrew Gavin 2009-2012
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

use DBI;
use Algorithm::LUHN qw/check_digit is_valid/;
use POSIX qw( floor ceil );
use Time::HiRes qw( gettimeofday );
use Digest::MD5 qw( md5_hex );
use File::Path qw (remove_tree);
use Archive::Extract;

# Status codes:
# -1 = deploying
# 0 = this script started
# 1 = files/directories whitelisted/blacklisted
# 2 = in process of grepping stuff
# 3 = done

my $profile = $ARGV[0];
my $target = $ARGV[1];
my $tracker = $ARGV[2];
my $scanname = $ARGV[3];
my $pid = $$;

my $db_admin_file = "../etc/db_admin";
my( $db_username, $db_password ) = "";
my( $username, $password, $mask, $scantype, $regex, $creditcards, $debug ) = "";
my( $domain, $exts, $ignore_exts, $dirs, $ignore_dirs, $zipfiles, $memory ) = "";
my @dir_array = @ext_array = @zip_array = @creditcard_array = ();
my %regexes = ();
my $total_file_size = 0;
my $total_files = 0;
my $bytes_done = 0;
my $files_done = 0;
my @all_files, @whitelist_files = ();
my $total_system_memory = $max_memory = "";
my $file_contents = "";
my $local_dir = "";

open( DB, $db_admin_file ) or die "BLAH";
my $db_line = <DB>;
close( DB );
chomp $db_line;
($db_username, $db_password) = split( ":", $db_line );

my $dbh_local = DBI->connect("DBI:mysql:database=OpenDLP;host=localhost",$db_username,$db_password);

my $string = "UPDATE systems SET pid=?,status=0 WHERE tracker=?";
my $sth_local = $dbh_local->prepare( $string );
$sth_local->execute( $pid, $tracker );
$sth_local->finish();

my $string = "SELECT username,password,domain,exts,ignore_exts,dirs,ignore_dirs,regex,debug,creditcards,zipfiles,memory,mask,scantype from profiles where profile=?";
my $sth_local = $dbh_local->prepare( $string );
$sth_local->execute( $profile );

# update log
update_log( "Attempting to start discovery" );

my $results = $sth_local->fetchrow_arrayref();
if( $$results[0] ne "" )
{
	$username = $$results[0];
	$password = $$results[1];
	$domain = $$results[2];
	$exts = $$results[3];
	$ignore_exts = $$results[4];
	$dirs = $$results[5];
	$ignore_dirs = $$results[6];
	$regex = $$results[7];
	$debug = $$results[8];
	$creditcards = $$results[9];
	$zipfiles = $$results[10];
	$memory = $$results[11];
	$mask = $$results[12];
	$scantype = $$results[13];

	$sth_local->finish();

	@dir_array = split( "\n", $dirs );
	@ext_array = split( "\n", $exts );
	@zip_array = split( "\n", $zipfiles );
	@creditcard_array = split( "\n", $creditcards );

	foreach( @dir_array )
	{
		$_ =~ s/\r$//g;
		$_ =~ s/\n$//g;
	}
	foreach( @ext_array )
	{
		$_ =~ s/\r$//g;
		$_ =~ s/\n$//g;
	}
	foreach( @zip_array )
	{
		$_ =~ s/\r$//g;
		$_ =~ s/\n$//g;
	}
	foreach( @creditcard_array )
	{
		$_ =~ s/\r$//g;
		$_ =~ s/\n$//g;
	}

	my @regex_array = split( ",", $regex );
	foreach( @regex_array )
	{
		my $string2 = "SELECT name,pattern FROM regexes WHERE number = ?";
		my $sth_local2 = $dbh_local->prepare( $string2 );
		$sth_local2->execute( $_ );
		my $results2 = $sth_local2->fetchrow_arrayref();
		$regexes{$$results2[0]} = $$results2[1];
		$sth_local2->finish();
	}

	update_log( "Retrieved all profile information" );
	update_log( "Ignore dirs option: $ignore_dirs" );
	update_log( "Ignore file extensions option: $ignore_exts" );

	if( $scantype eq "unix_agentless" )
	{
		do_unix_agentless();
		update_log( "Done with UNIX agentless file system scan" );
	}

	my $string = "UPDATE systems SET status=3,control=? WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( 'finished', $tracker );
}
else
{
	# could not find policy info
	update_log( "Could not find policy...quitting" );
	my $string = "UPDATE systems SET status=3,control=? WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( 'finished', $tracker );
}
$sth_local->finish();
$dbh_local->disconnect();

sub do_unix_agentless
{
	get_system_memory();
	$max_memory = floor($memory * $total_system_memory);
	# reduce it to a multiple of 4096 because we read files in 4096 byte chunks later
	$max_memory = $max_memory - ($max_memory % 4096);
	update_log( "Total system memory is $total_system_memory; limiting memory usage to $max_memory" );

	update_log( "Starting to enumerate files and directories" );

	if( !(-d "/tmp/OpenDLP" ))
	{
		mkdir "/tmp/OpenDLP";
		if( $debug > 0 )
		{
			update_log( "\"/tmp/OpenDLP\" did not exist. I created it." );
		}
	}

	# create local directory at which to mount remote sshfs
	my $subdir = 1;
	while( (mkdir "/tmp/OpenDLP/$subdir") == 0 )
	{
		$subdir++;
	}
	$local_dir = "/tmp/OpenDLP/$subdir";

	# mount remote SSHFS at $local_dir
	my $command = "echo ";
	for( my $x = 0; $x < length( $password ); $x++ )
	{
		my $char = substr( $password, $x, 1 );
		$command .= "\\" . $char;
	}
	$command .= " | sshfs ";
	for( my $x = 0; $x < length( $username ); $x++ )
	{
		my $char = substr( $username, $x, 1 );
		$command .= "\\" . $char;
	}
	$command .= "\@" . "$target" . ":/ $local_dir -o idmap=none,password_stdin,nonempty,UserKnownHostsFile=/dev/null,StrictHostKeyChecking=no";
	`$command`;

	# insert directory into DB table so we know what to unmount if scan gets killed
	my $full_mountdir = "/tmp/OpenDLP/" . $subdir;
	my $string2 = "INSERT INTO agentless_mount SET tracker=?,scan=?,mountdir=?";
	my $sth_local2 = $dbh_local->prepare( $string2 );
	$sth_local2->execute( $tracker, $scanname, $full_mountdir );
	$sth_local2->finish();

	# walk directory structures
	if( $ignore_dirs eq "everything" || $ignore_dirs eq "ignore" )
	{
		process_dir( "/" );
	}
	elsif( $ignore_dirs eq "allow" )
	{
		# process_dir() each one
		foreach( @dir_array )
		{
			process_dir( $_ );
		}
	}

	# check files for whitelist/blacklist extensions
#	update_log( "Checking file extensions for whitelist/blacklist rules" );
#	whitelist_files();

	# insert all files so we can track where to resume if scan is interrupted.
	# after successfully processing each file, they will be deleted from the table.
#	my $sth_local = "";
#	my $length_whitelist_files = @whitelist_files;
#	if( $length_whitelist_files > 0 )
#	{
#		foreach( @whitelist_files )
#		{
#			my $string = "INSERT INTO agentless SET tracker=?, scan=?, file=?";
#			$sth_local = $dbh_local->prepare( $string );
#			$sth_local->execute( $tracker, $scanname, $_ );
#		}
#		$sth_local->finish();

	my $localtime = time();
	my $string = "UPDATE systems SET status=?,updated=?,filestotal=?,bytestotal=? WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( '1', $localtime, $total_files, $total_file_size, $tracker );
	$sth_local->finish();

	update_log( "Searching files for regular expressions" );
	do_read();
#	}
#	else
#	{
#		update_log( "No files to process...ending." );
#	}

	# umount $local_dir
	`fusermount -u $local_dir`;
	my $ret = rmdir $local_dir;
	if( $ret == 0 )
	{
		update_log( "Could not remove $local_dir: $!" );
	}

	# delete mount dir from DB
	my $string2 = "DELETE FROM agentless_mount WHERE tracker=? AND scan=? AND mountdir=?";
	my $sth_local2 = $dbh_local->prepare( $string2 );
	$sth_local2->execute( $tracker, $scanname, $full_mountdir );
	$sth_local2->finish();
}

sub do_read
{
	my $filesize = "";

	my $string = "UPDATE systems SET status=2,control=? WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( 'running', $tracker );
	$sth_local->finish();

	my $string = "SELECT file from agentless where tracker=? AND scan=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( $tracker, $scanname );
	while( my $results = $sth_local->fetchrow_arrayref() )
	{
		$file_contents = $filesize = "";
		my $file = $$results[0];

		my $absolute_file = $local_dir . "/" . $file;
		$absolute_file =~ s/\/+/\//g;
		# get filesize
		my @tab = stat( $absolute_file );
		if( $#tab != 0 )
		{
			$filesize = $tab[7];
			$total_file_size += $filesize;
		}

		my $loops = ceil( $filesize / $max_memory );

		open( my $fd, "<", $absolute_file );
		if( $fd ne "" )
		{
			for( my $x = 0; $x < $loops; $x++ )
			{
				seek( $fd, $x * $max_memory, 0 );
				$file_contents = "";
				my $y = 0;

				# read 4096 bytes at a time
				while( defined(read( $fd, my $buffer, 4096 )))
				{
					$y++;
					$file_contents .= $buffer;
					if( $buffer eq '' || ($y * 4096) >= $max_memory )
					{
						last;
					}
				}

				my $loop = $x + 1;

				# pass by reference
				do_grep( \$file_contents, $file, "", $loop - 1);
			}
			close( $fd );
		}
		else
		{
			update_log( "Cannot open $absolute_file" );
		}

		# check if it's a ZIP file
		my $found_zip = 0;
		foreach( @zip_array )
		{
			my $extension = $file;
			$extension =~ s/.*\.//g;
			if( $_ =~ /^$extension$/i )
			{
				$found_zip = 1;
			}
		}
		if( $found_zip == 1 )
		{
			do_unzip( $file );
		}

		my $string2 = "DELETE FROM agentless where file=? AND tracker=? AND scan=?";
		my $sth_local2 = $dbh_local->prepare( $string2 );
		$sth_local2->execute( $file, $tracker, $scanname );

		my $localtime = time();
		$bytes_done += $filesize;
		$files_done++;
		$string2 = "UPDATE systems SET status=?,updated=?,filesdone=?,bytesdone=? WHERE tracker=?";
		$sth_local2 = $dbh_local->prepare( $string2 );
		$sth_local2->execute( '2', $localtime, $files_done, $bytes_done, $tracker );
		$sth_local2->finish();
	}
	$sth_local->finish();
}

sub do_unzip
{
	my $file = shift;
	my $file_absolute = $local_dir . "/" . $file;
	my $filesize = "";

	$file_absolute =~ s/\/+/\//g;

	update_log( "Found zip $file" );

	if( !(-d "/tmp/OpenDLP" ))
	{
		mkdir "/tmp/OpenDLP";
		if( $debug > 0 )
		{
			update_log( "\"/tmp/OpenDLP\" did not exist. I created it." );
		}
	}

	my $subdir_unzip = 1;
	while( (mkdir "/tmp/OpenDLP/$subdir_unzip") == 0 )
	{
		$subdir_unzip++;
	}

	# insert directory into DB table so we know what to delete if scan gets killed
	my $full_unzipdir = "/tmp/OpenDLP/" . $subdir_unzip;
	my $string2 = "INSERT INTO agentless_zip SET tracker=?,scan=?,unzipdir=?";
	my $sth_local2 = $dbh_local->prepare( $string2 );
	$sth_local2->execute( $tracker, $scanname, $full_unzipdir );
	$sth_local2->finish();

	if( $debug > 0 )
	{
		update_log( "created directory \"/tmp/OpenDLP/$subdir_unzip\" for ZIP file $file_absolute" );
	}

	my $ae = Archive::Extract->new( archive => "$file_absolute", type => "zip" );
	if( $ae->is_zip )
	{
		mkdir "/tmp/OpenDLP/$subdir_unzip/files";
		my $ok = $ae->extract( to => "/tmp/OpenDLP/$subdir_unzip/files" );

		my $files = $ae->files;
		foreach my $relative_zip_content( @$files )
		{
			if( is_zipcontent_whitelisted( $relative_zip_content ))
			{
				my $absolute_zip_content = "/tmp/OpenDLP/$subdir_unzip/files/" . $relative_zip_content;
				# get filesize
				my @tab = stat( $absolute_zip_content );
				if( $#tab != 0 )
				{
					$filesize = $tab[7];
				}

				my $loops = ceil( $filesize / $max_memory );

				open( my $fd, "<", $absolute_zip_content );
				if( $fd ne "" )
				{
					for( my $x = 0; $x < $loops; $x++ )
					{
						seek( $fd, $x * $max_memory, 0 );
						$file_contents = "";
						my $y = 0;

						# read 4096 bytes at a time
						while( defined(read( $fd, my $buffer, 4096 )))
						{
							$y++;
							$file_contents .= $buffer;
							if( $buffer eq '' || ($y * 4096) >= $max_memory )
							{
								last;
							}
						}

						my $loop = $x + 1;

						# pass by reference
						do_grep( \$file_contents, $relative_zip_content, $file, $loop - 1);
					}
					close( $fd );
				}
			}
		}
	}

	# recursively delete "/tmp/OpenDLP/$subdir_unzip"
	remove_tree( "/tmp/OpenDLP/$subdir_unzip" );

	# insert directory into DB table so we know what to delete if scan gets killed
	my $string2 = "DELETE FROM agentless_zip WHERE tracker=? AND scan=? AND unzipdir=?";
	my $sth_local2 = $dbh_local->prepare( $string2 );
	$sth_local2->execute( $tracker, $scanname, $full_unzipdir );
	$sth_local2->finish();
}

sub is_zipcontent_whitelisted
{
	my $file = shift;

	my $found_match = 0;
	my $file_ext = $file;
	$file_ext =~ s/^.*\.//g;

	foreach( @ext_array )
	{
		if( $file_ext =~ /^$_$/i )
		{
			$found_match = 1;
		}
	}

	if( $ignore_exts eq "everything" )
	{
		return 1;
	}
	elsif( $ignore_exts eq "ignore" && $found_match == 0 )
	{
		return 1;
	}
	elsif( $ignore_exts eq "allow" && $found_match == 1 )
	{
		return 1;
	}
}

sub do_grep
{
	my $fileref = shift;
	my $filename = shift;
	my $zipfile = shift;
	my $offset_multiplier = shift;
	my $md5 = "";

	my $possible_find = 0;
	my $is_cc_regex = 0;
	my $found_valid_cc = "";

	# cycle through regexes
	foreach my $regexname( sort( keys( %regexes )))
	{
		# rewind all the way to the beginning
		pos( $$fileref ) = 0;

		while( $$fileref =~ m/$regexes{$regexname}/g )
		{
			my $match = $&;
			$possible_find = 1;
			my $end_position = pos( $$fileref );
			my $begin_position = $end_position - length( $match );
			my $begin_position_print = ($offset_multiplier * $max_memory) + $begin_position;

			foreach( @creditcard_array )
			{
				if( $_ eq $regexname )
				{
					$is_cc_regex = 1;
					my $length_match = length( $match );
					my $match_copy = "";
					my $x = 0;
					while( $x < $length_match )
					{
						if( substr( $match, $x, 1 ) =~ /[0-9]/ )
						{
							$match_copy .= substr( $match, $x, 1 );
						}
						$x++;
					}
					if( do_luhn( $match_copy ))
					{
						$found_valid_cc = 1;
					}
					else
					{
						$found_valid_cc = 0;
					}
				}
			}
			if( $found_valid_cc == 1 || $is_cc_regex == 0 )
			{
				if( $md5 eq "" )
				{
					$md5 = md5_hex( $$fileref );
				}
				my $match_printme = "";
				if( $mask == 1 )
				{
					$match_printme = filterme( $match );
				}
				else
				{
					$match_printme = $match;
				}

				my $filename_printme = "";
				if( $zipfile ne "" )
				{
					$filename_printme = $zipfile . ":" . $filename;
				}
				else
				{
					$filename_printme = $filename;
				}

#				update_log( "Regex: $regexname || Data: $match || File: $filename || Offset: $begin_position_print" );
				my $string = "INSERT INTO results SET scan=?,system=?,type=?,pattern=?,file=?,offset=?,md5=?,tracker=?,is_false=\"0\"";
				my $sth_local = $dbh_local->prepare( $string );
				$sth_local->execute( $scanname,$target,$regexname,$match_printme,$filename_printme,$begin_position_print,$md5,$tracker );

				$sth_local->finish();
			}

			# advance one byte, try to match more stuff
			pos( $$fileref ) = $begin_position + 1;
		}
	}
	
}

sub do_luhn
{
	my $number = shift;
	my $c = check_digit( $number );
	if( is_valid( $number ))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

sub whitelist_file
{
	my $file = shift;
	my $found_match = 0;
	my $add_to_db = 0;
	my $file_ext = $file;
	$file_ext =~ s/^.*\.//g;

	foreach( @ext_array )
	{
		if( $file_ext =~ /^$_$/i )
		{
			$found_match = 1;
		}
	}

	if( $ignore_exts eq "everything" )
	{
#		push @whitelist_files, $file;
		$add_to_db = 1;

		# get filesize
		my @tab = stat( $file );
		if( $#tab != 0 )
		{
			my $filesize = $tab[7];
			$total_file_size += $filesize;
		}
		$total_files++;
	}
	elsif( $ignore_exts eq "ignore" )
	{
		if( $found_match == 0 )
		{
#			push @whitelist_files, $file;
			$add_to_db = 1;

			# get filesize
			my @tab = stat( $file );
			if( $#tab != 0 )
			{
				my $filesize = $tab[7];
				$total_file_size += $filesize;
			}
			$total_files++;
		}
	}
	elsif( $ignore_exts eq "allow" )
	{
		if( $found_match == 1 )
		{
#			push @whitelist_files, $file;
			$add_to_db = 1;

			# get filesize
			my @tab = stat( $file );
			if( $#tab != 0 )
			{
				my $filesize = $tab[7];
				$total_file_size += $filesize;
			}
			$total_files++;
		}
	}
	if( $add_to_db == 1 )
	{
		my $string = "INSERT INTO agentless SET tracker=?, scan=?, file=?";
		my $sth_local = $dbh_local->prepare( $string );
		$sth_local->execute( $tracker, $scanname, $file );
		$sth_local->finish();

		if( $debug > 1 ) { update_log( "$file will be scanned" ); }
	}
}


# this walks the directories and whitelists/blacklists them
sub process_dir
{
	my $relative_dir = shift;
	if( scan_dir( $relative_dir ) == 1 )
	{
		my $cwd = $local_dir . $relative_dir;
		update_log( "Processing this directory on $target: $relative_dir (aka $cwd)" );
		opendir( my $dh, $cwd );
		if( $debug > 1 ) { update_log( "Opened dir: $cwd" ); }
		my @files = readdir( $dh );
		closedir( $dh );
		foreach my $file( @files )
		{
			my $temp_file = $cwd . "/" . $file;
			$temp_file =~ s/\/+/\//g;
			if( $file ne "." && $file ne ".." )
			{
#				update_log( "File in dir: $temp_file" );
				if( -d $temp_file )
				{
					my $new_dir = $relative_dir . "/" . $file;
					$new_dir =~ s/\/+/\//g;
					if( $debug > 2 ) { update_log( "Dir: $new_dir (temp_file = $temp_file)" ); }
					process_dir( $new_dir );
				}
				elsif( -f $temp_file )
				{
					my $new_file = $relative_dir . "/" . $file;
					$new_file =~ s/\/+/\//g;
#					push @all_files, $new_file;
					whitelist_file( $new_file );
					if( $debug > 2 ) { update_log( "File: $new_file (temp_file = $temp_file)" ); }
				}
			}
		}
	}
	else
	{
		if( $debug > 1 ) { update_log( "Will not scan dir: $relative_dir" ); }
	}
}

sub process_file
{
	my $file = shift;
}

sub scan_dir
{
	my $dir = shift;

	if( $ignore_dirs eq "everything" || $ignore_dirs eq "allow" )
	{
		return 1;
	}
	elsif( $ignore_dirs eq "ignore" )
	{
		my $found_match = 0;
		foreach my $dir_in_list( @dir_array )
		{
			if( $dir =~ /^$dir_in_list/i )
			{
				$found_match = 1;
			}
		}
		if( $found_match == 1 )
		{
			return 0;
		}
		else
		{
			return 1;
		}
	}
}

sub update_log
{
	my $log_message = shift;
	my $localtime = getmicroseconds();
	my $string = "INSERT INTO logs SET tracker=?,data=?,updated=?,scan=?,profile=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( $tracker, $log_message, $localtime, $scanname, $profile );
	$sth_local->finish();
}

sub print_log
{
	my $string = shift;
	open( BLAH, ">>/tmp/blah.txt" );
	print BLAH $string;
	close( BLAH );
}

sub filterme
{
	my $text = shift;
	my $filtered = "";

	for( my $x = 0; $x < length( $text ); $x++ )
	{
		my $char = substr( $text, $x, 1 );
		if( $x <= (floor( length( $text ) * .75)) )
		{
			$filtered .= "X";
		}
		elsif( $char !~ /[0-9A-Z\~\`\!\@\#\$\%\^\&\*\(\)\_\-\=\+\[\{\]\}\\\|\;\:\'\"\,\<\.\>\/\?\ ]/i )
		{
			$filtered .= "?";
		}
		else
		{
			$filtered .= $char;
		}
	}
	return $filtered;
}

sub getmicroseconds
{
	my( $seconds, $microseconds ) = gettimeofday;
	while( length( $microseconds ) < 6 )
	{
		$microseconds = "0" . $microseconds;
	}
	return "$seconds.$microseconds";
}

sub get_system_memory
{
	my $os = `uname`;
	chomp $os;
	my $memory = "";

	if( $os eq "Linux" )
	{
		open( MEMINFO, "/proc/meminfo" );
		while( my $line = <MEMINFO> )
		{
			chomp $line;
			if( $line =~ /^MemTotal:/ )
			{
				$memory = $line;
			}
		}
		close( MEMINFO );
		$memory =~ s/^MemTotal://g;
		$memory =~ s/^\ +//g;
		$memory =~ s/\ .*$//g;
		$memory *= 1024;
	}

	$total_system_memory = $memory;
}
