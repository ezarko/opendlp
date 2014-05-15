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
use Filesys::SmbClient;
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
my( $domain, $exts, $ignore_exts, $dirs, $ignore_dirs, $zipfiles, $memory, $hash ) = "";
my @dir_array = @ext_array = @zip_array = @creditcard_array = ();
my %regexes = ();
my $total_file_size = 0;
my $total_files = 0;
my $bytes_done = 0;
my $files_done = 0;
my $smb = "";
my @all_files, @whitelist_files = ();
my $total_system_memory = $max_memory = "";
my $file_contents = "";
my $target_ip = $target_share = $target_combined = "";

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

my $string = "SELECT username,password,domain,exts,ignore_exts,dirs,ignore_dirs,regex,debug,creditcards,zipfiles,memory,mask,hash,scantype from profiles where profile=?";
my $sth_local = $dbh_local->prepare( $string );
$sth_local->execute( $profile );

# update log
update_log( "Attempting to start discovery" );

my $results = $sth_local->fetchrow_arrayref();
if( $$results[14] ne "" )
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
	$hash = $$results[13];
	$scantype = $$results[14];

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

	if( $hash ne "" )
	{
		$ENV{'SMBHASH'} = $hash;
		update_log( "Using pass-the-hash instead of password" );
	}

	update_log( "Retrieved all profile information" );
	update_log( "Ignore dirs option: $ignore_dirs" );
	update_log( "Ignore file extensions option: $ignore_exts" );

	if( $scantype eq "win_agentless" )
	{
		do_win_agentless();
		update_log( "Done with Microsoft Windows agentless file system scan" );
	}
	elsif( $scantype eq "win_share" )
	{
		do_win_share();
		update_log( "Done with Microsoft Windows share scan" );
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

sub do_win_agentless
{
	get_system_memory();
	$max_memory = floor($memory * $total_system_memory);
	# reduce it to a multiple of 4096 because we read files in 4096 byte chunks later
	$max_memory = $max_memory - ($max_memory % 4096);
	update_log( "Total system memory is $total_system_memory; limiting memory usage to $max_memory" );

	update_log( "Starting to enumerate files and directories" );
	$smb = new Filesys::SmbClient( username => $username, password => $password, workgroup => $domain );

	# walk directory structures
	if( $ignore_dirs eq "everything" || $ignore_dirs eq "ignore" )
	{
		# process_dir() c:\ through z:\
		my @drive_array = ( "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" );
		foreach( @drive_array )
		{
			process_dir( "smb://$target/$_\$" );
		}
	}
	elsif( $ignore_dirs eq "allow" )
	{
		# process_dir() each one
		foreach( @dir_array )
		{
			my $dir_copy = $_;
			substr( $dir_copy, 1, 1, "\$" );
			$dir_copy =~ s/\\/\//g;
			update_log( "processing smb://$target/$dir_copy" );
			process_dir( "smb://$target/$dir_copy" );
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

	update_log( "Done whitelisting files. Now searching files for regular expressions." );
	do_read();
#	}
#	else
#	{
#		update_log( "No files to process...ending." );
#	}
}

sub do_win_share
{
	get_system_memory();
	$max_memory = floor($memory * $total_system_memory);
	# reduce it to a multiple of 4096 because we read files in 4096 byte chunks later
	$max_memory = $max_memory - ($max_memory % 4096);
	update_log( "Total system memory is $total_system_memory; limiting memory usage to $max_memory" );

	update_log( "Starting to enumerate files and directories" );
	$smb = new Filesys::SmbClient( username => $username, password => $password, workgroup => $domain );

	# $target is coming in as "\\1.2.3.4\Share"
	# need to extract IP address and full share path
	my @target_array = split( /\\/, $target );
	$target_ip = $target_array[2];
	my $length_target_array = @target_array;
	for( my $x = 3; $x < $length_target_array; $x++ )
	{
		$target_share .= "/" . $target_array[$x];
	}

	$target_combined = "$target_ip/$target_share";
	$target_combined =~ s/\/+/\//g;

	# walk directory structures
	if( $ignore_dirs eq "everything" || $ignore_dirs eq "ignore" )
	{
		update_log( "processing smb://$target_combined" );
		process_dir_share( "smb://$target_combined" );
	}
	elsif( $ignore_dirs eq "allow" )
	{
		# process_dir() each one
		foreach( @dir_array )
		{
			my $dir_copy = $_;
			$dir_copy =~ s/\\/\//g;
			my $temp_target_combined = $target_combined . "/" . $dir_copy;
			$temp_target_combined =~ s/\/+/\//g;
			update_log( "processing smb://$temp_target_combined" );
			process_dir_share( "smb://$temp_target_combined" );
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

		# get filesize
		my @tab = $smb->stat( $file );
		if( $#tab != 0 )
		{
			$filesize = $tab[7];
			$total_file_size += $filesize;
		}

		my $loops = ceil( $filesize / $max_memory );

		my $fd = $smb->open( $file, '0666' ) or $smb_error = $!;
		if( $smb_error eq "" )
		{
			for( my $x = 0; $x < $loops; $x++ )
			{
				$smb->seek( $fd, $x * $max_memory );
				$file_contents = "";
				my $y = 0;

				# read 4096 bytes at a time
				while( defined( my $buffer = $smb->read( $fd, 4096 )))
				{
					$y++;
					$file_contents .= $buffer;
					if( $buffer eq '' || ($y * 4096) >= $max_memory )
					{
						last;
					}
#					last if $buffer eq '';
				}

				my $length_file_contents = length( $file_contents );
				my $loop = $x + 1;
#				update_log( "Loaded $length_file_contents bytes from file $file. this is loop $loop" );

				# pass by reference
				do_grep( \$file_contents, $file, "", $loop - 1);
			}
			$smb->close( $fd );
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
	my $file_copy = $file;
	my $filesize = "";

	$file_copy =~ s/.*\///g;

	update_log( "Found zip $file" );

	if( !(-d "/tmp/OpenDLP" ))
	{
		mkdir "/tmp/OpenDLP";
		if( $debug > 0 )
		{
			update_log( "\"/tmp/OpenDLP\" did not exist. I created it." );
		}
	}

	my $subdir = 1;
	while( (mkdir "/tmp/OpenDLP/$subdir") == 0 )
	{
		$subdir++;
	}

	# insert directory into DB table so we know what to delete if scan gets killed
	my $full_unzipdir = "/tmp/OpenDLP/" . $subdir;
	my $string2 = "INSERT INTO agentless_zip SET tracker=?,scan=?,unzipdir=?";
	my $sth_local2 = $dbh_local->prepare( $string2 );
	$sth_local2->execute( $tracker, $scanname, $full_unzipdir );
	$sth_local2->finish();

	if( $debug > 0 )
	{
		update_log( "created directory \"/tmp/OpenDLP/$subdir\" for ZIP file $file_copy" );
	}

	$file_copy = "/tmp/OpenDLP/$subdir/$file_copy";

	# copy it to /tmp. This is ugly, I know. However, since we chop up large files
	# into segments, it is possible we would be chopping a ZIP file. If we chop a
	# ZIP, then it won't unzip. To be safe, I am copying the entire thing again.
	my $fd = $smb->open( $file, '0666' ) or $smb_error = $!;
	if( $smb_error eq "" )
	{
		unlink $file_copy;
		open( LOCAL, ">>$file_copy" );
		# read 4096 bytes at a time, write them to disk
		while( defined( my $buffer = $smb->read( $fd, 4096 )))
		{
			
			print LOCAL $buffer;
			if( $buffer eq '' )
			{
				last;
			}
		}
		close( LOCAL );
	}

	if( -f $file_copy )
	{
		my $ae = Archive::Extract->new( archive => "$file_copy", type => "zip" );
		if( $ae->is_zip )
		{
			mkdir "/tmp/OpenDLP/$subdir/files";
			my $ok = $ae->extract( to => "/tmp/OpenDLP/$subdir/files" );

			my $files = $ae->files;
			foreach my $relative_zip_content( @$files )
			{
				if( is_zipcontent_whitelisted( $relative_zip_content ))
				{
					my $absolute_zip_content = "/tmp/OpenDLP/$subdir/files/" . $relative_zip_content;
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
	}

	# recursively delete "/tmp/OpenDLP/$subdir"
	remove_tree( "/tmp/OpenDLP/$subdir" );

	# remove entry from DB
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
		my @tab = $smb->stat( $file );
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
			my @tab = $smb->stat( $file );
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
			my @tab = $smb->stat( $file );
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
	my $dir = shift;
	if( scan_dir( $dir ) == 1 )
	{
		my $fd = $smb->opendir( $dir );
		if( $fd != 0 )
		{
			foreach my $n( $smb->readdir_struct($fd) )
			{
				if( $n->[1] ne "." && $n->[1] ne ".." )
				{
					if( $n->[0] == SMBC_DIR )
					{
						my $new_dir = $dir . "/$n->[1]";
						process_dir( $new_dir );
					}
					elsif( $n->[0] == SMBC_FILE )
					{
						my $new_file = $dir . "/$n->[1]";
						whitelist_file( $new_file );
					}
				}
			}
			$smb->closedir( $fd );
		}
	}
}

# this walks the directories and whitelists/blacklists them
sub process_dir_share
{
	my $dir = shift;
	if( $debug > 1 ) { update_log( "Checking if we should scan $dir" ); }
	if( scan_dir_share( $dir ) == 1 )
	{
		if( $debug > 0 ) { update_log( "Scanning $dir" ); }
		my $fd = $smb->opendir( $dir );
		if( $fd != 0 )
		{
			foreach my $n( $smb->readdir_struct($fd) )
			{
				if( $n->[1] ne "." && $n->[1] ne ".." )
				{
					if( $n->[0] == SMBC_DIR )
					{
						my $new_dir = $dir . "/$n->[1]";
						process_dir_share( $new_dir );
					}
					elsif( $n->[0] == SMBC_FILE )
					{
						my $new_file = $dir . "/$n->[1]";
#						push @all_files, $new_file;
						whitelist_file( $new_file );
						if( $debug > 1 ) { update_log( "I see $new_file and will whitelist/blacklist it" ); }
					}
				}
			}
			$smb->closedir( $fd );
		}
	}
	else
	{
		if( $debug > 0 ) { update_log( "Ignoring $dir" ); }
	}
}

sub scan_dir
{
	my $dir = shift;
	my $dir_copy = $dir;
	$dir_copy =~ s/^smb:\/\/(.*?)\///g;
	substr( $dir_copy, 1, 1, ":" );
	$dir_copy =~ s/\//\\/g;
	$dir_copy .= "\\";
	my $found_match = 0;
	my $dir_in_list = "";
	my @dir_array_copy = @dir_array;

	if( $ignore_dirs eq "everything" || $ignore_dirs eq "allow" )
	{
		return 1;
	}
	elsif( $ignore_dirs eq "ignore" )
	{
		foreach $dir_in_list( @dir_array_copy )
		{
			if( $dir_in_list !~ /\\$/ ) { $dir_in_list .= "\\"; }
			$dir_in_list =~ s/\\/\\\\/g;
			if( $dir_copy =~ /^$dir_in_list/i )
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

sub scan_dir_share
{
	my $dir = shift;
	if( $ignore_dirs eq "everything" || $ignore_dirs eq "allow" )
	{
		return 1;
	}
	elsif( $ignore_dirs eq "ignore" )
	{
		my @dir_array_incoming = split( "/", $dir );
		my $length_dir_array = @dir_array_incoming;
		my $target_ip_split = $dir_array_incoming[2];
		my $target_share_copy = $target_share;
		$target_share_copy =~ s/^\///g;
		$target_share_copy =~ s/\/$//g;
		my @original_share = split( "/", $target_share_copy );
		my $length_original_share = @original_share;
		update_log( "Length of original share: $length_original_share" );
		my $start_comparing_dirs = $length_original_share + 3;
		my $x = $start_comparing_dirs;
		my $compare_incoming_dir = "";
		for( $x; $x < $length_dir_array; $x++ )
		{
			$compare_incoming_dir .= $dir_array_incoming[$x] . "/";
		}

		my $found_match = 0;
		my $dir_in_list = "";
		my @dir_array_copy = @dir_array;

		foreach $dir_in_list( @dir_array_copy )
		{
			$dir_in_list =~ s/\\/\//g;
			if( $dir_in_list !~ /\/$/ ) { $dir_in_list .= "/"; }

			if( $compare_incoming_dir =~ /^$dir_in_list/i )
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
