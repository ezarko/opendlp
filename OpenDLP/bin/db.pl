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
use POSIX qw( floor );
use Time::HiRes qw( gettimeofday );

# Status codes:
# -1 = deploying
# 0 = this script started
# 1 = schema enumeration complete
# 2 = in process of grepping stuff
# 3 = done

my $profile = $ARGV[0];
my $target = $ARGV[1];
my $tracker = $ARGV[2];
my $scanname = $ARGV[3];
my $pid = $$;

my $db_admin_file = "../etc/db_admin";
my( $db_username, $db_password ) = "";
my( $username, $password, $mask, $ignore_dbs, $dbs, $ignore_tables, $tables, $ignore_columns, $columns, $rows, $scantype, $regex, $creditcards, $debug ) = "";
my $total_databases = $total_tables = $total_columns = 0;
my $databases_done = $tables_done = $columns_done = 0;
my @db_array = @table_array = @column_array = @creditcard_array = ();
my %data = %whitelist_data = %regexes = ();

open( DB, $db_admin_file ) or die "BLAH";
my $db_line = <DB>;
close( DB );
chomp $db_line;
($db_username, $db_password) = split( ":", $db_line );

my $dbh_local = DBI->connect("DBI:mysql:database=OpenDLP;host=localhost",$db_username,$db_password);

my $string = "UPDATE systems SET pid=?,status=0 WHERE tracker=?";
my $sth_local = $dbh_local->prepare( $string );
$sth_local->execute( $pid, $tracker );

my $string = "SELECT username,password,mask,ignore_dbs,dbs,ignore_tables,tables,ignore_columns,columns,rows,scantype,regex,creditcards,debug FROM profiles where profile=?";
my $sth_local = $dbh_local->prepare( $string );
$sth_local->execute( $profile );

# update log
update_log( "Attempting to start discovery" );

my $results = $sth_local->fetchrow_arrayref();
if( $$results[0] ne "" )
{
	$username = $$results[0];
	$password = $$results[1];
	$mask = $$results[2];
	$ignore_dbs = $$results[3];
	$dbs = $$results[4];
	$ignore_tables = $$results[5];
	$tables = $$results[6];
	$ignore_columns = $$results[7];
	$columns = $$results[8];
	$rows = $$results[9];
	$scantype = $$results[10];
	$regex = $$results[11];
	$creditcards = $$results[12];
	$debug = $$results[13];

	@db_array = split( "\n", $dbs );
	@table_array = split( "\n", $tables );
	@column_array = split( "\n", $columns );
	@creditcard_array = split( "\n", $creditcards );

	foreach( @db_array )
	{
		$_ =~ s/\r$//g;
		$_ =~ s/\n$//g;
	}
	foreach( @table_array )
	{
		$_ =~ s/\r$//g;
		$_ =~ s/\n$//g;
	}
	foreach( @column_array )
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

	if( $scantype eq "mssql_agentless" )
	{
		update_log( "Starting Microsoft SQL server scan" );
		do_mssql_agentless();
		update_log( "Done with Microsoft SQL server scan" );
	}
	elsif( $scantype eq "mysql_agentless" )
	{
		update_log( "Starting MySQL scan" );
		do_mysql_agentless();
		update_log( "Done with MySQL scan" );
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
	$sth_local->finish();
}
$sth_local->finish();
$dbh_local->disconnect();

sub do_mysql_agentless
{
	# get all dbs/tables/columns
	my $dbh = DBI->connect("DBI:mysql:database=information_schema;host=$target",$username,$password);
	if( $dbh )
	{
		update_log( "Successfully authenticated to database server" );
	}
	else
	{
		update_log( "Could not authenticate to MySQL database server...quitting" );
		my $string = "UPDATE systems SET status=3,control=? WHERE tracker=?";
		my $sth_local = $dbh_local->prepare( $string );
		$sth_local->execute( 'finished', $tracker );
		$sth_local->finish();
		$dbh_local->disconnect();
		exit(0);
	}

	my $string = "SELECT DISTINCT table_schema,table_name,column_name FROM columns";
	my $sth = $dbh->prepare( $string );
	$sth->execute();
	while( my $results = $sth->fetchrow_arrayref() )
	{
		my $database = $$results[0];
		my $table = $$results[1];
		my $column = $$results[2];
		push @{$data{$database}{$table}}, $column;
	}
	$sth->finish();

	my $string = "UPDATE systems SET status=1 WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( $tracker );
	$sth_local->finish();

	update_log( "Done enumerating entire database server schema" );
	# figure out what we're going to scan based on policy
	whitelist_schema();
	update_log( "Done whitelisting/blacklisting database server schema...beginning to parse actual data" );

	my $string = "UPDATE systems SET status=?,dbtotal=?,tabletotal=?,columntotal=? WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( "2", $total_databases, $total_tables, $total_columns, $tracker );
	$sth_local->finish();

	# grab actual data
	foreach my $db( sort( keys( %whitelist_data )))
	{
		update_log( "Starting with database \"$db\"" );
		$dbh->do( "use \`$db\`" );
		foreach my $tbl( sort( keys( %{$whitelist_data{$db}} )))
		{
			my $length_col = @{$whitelist_data{$db}{$tbl}};
			if( $length_col > 0 )
			{
				my $select = "SELECT ";
				my $counter = 0;
				foreach my $col( @{$whitelist_data{$db}{$tbl}} )
				{
					$select .= "\`$col\`";
					$counter++;
					if( $counter < $length_col )
					{
						$select .= ",";
					}
				}
				$select .= " FROM \`$tbl\`";
				if( $rows > 0 )
				{
					$select .= " LIMIT $rows";
				}
				my $sth = $dbh->prepare( $select );
				$sth->execute();

				# MySQL considers the first row as 1, not 0
				my $row_counter = 1;
				while( my $results = $sth->fetchrow_arrayref() )
				{
					my $col_counter = 0;
					foreach my $coldata( @{$results} )
					{
						my $curr_column = $whitelist_data{$db}{$tbl}[$col_counter];
						foreach my $key( sort( keys( %regexes )))
						{
							my( $result, $possible_string ) = find_data( $coldata, $key );
							if( $result == 1 )
							{
								my $string_copy = "";
								if( $mask == 1 )
								{
									$string_copy = filterme( $possible_string );
								}
								else
								{
									$string_copy = $possible_string;
								}
								my $string = "INSERT INTO results SET scan=?,system=?,type=?,pattern=?,tracker=?,db=?,tbl=?,col=?,row=?,is_false=\"0\"";
								my $sth_local = $dbh_local->prepare( $string );
								$sth_local->execute( $scanname, $target, $key, $string_copy, $tracker, $db, $tbl, $curr_column, $row_counter );
								$sth_local->finish();
							}
						}
						$col_counter++;
					}
					$row_counter++;
				}
				$columns_done += @{$whitelist_data{$db}{$tbl}};
			}
			# update column, table counter in systems table
			$tables_done++;
			my $localtime = time();
			my $update = "UPDATE systems SET tabledone=?,columndone=?,updated=? WHERE tracker=?";
			my $sth_local = $dbh_local->prepare( $update );
			$sth_local->execute( $tables_done, $columns_done, $localtime, $tracker );
			$sth_local->finish();

			update_log( "Done with table \"$tbl\" and $length_col column(s)" );
		}
		# update database counter in systems table
		$databases_done++;
		my $localtime = time();
		my $update = "UPDATE systems SET dbdone=?,updated=? WHERE tracker=?";
		my $sth_local = $dbh_local->prepare( $update );
		$sth_local->execute( $databases_done, $localtime, $tracker );
		$sth_local->finish();

		update_log( "Done with database \"$db\"" );
	}
	$dbh->disconnect();
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

sub do_mssql_agentless
{
	# get all DBs, tables, columns
	my $dsn = "DBI:Sybase:server=$target";

	my $dbh = DBI->connect( $dsn, $username, $password );
	if( $dbh )
	{
		update_log( "Successfully authenticated to database server" );
	}
	else
	{
		update_log( "Could not authenticate to database server...quitting" );
		my $string = "UPDATE systems SET status=3,control=? WHERE tracker=?";
		my $sth_local = $dbh_local->prepare( $string );
		$sth_local->execute( 'finished', $tracker );
		$sth_local->finish();
		$dbh_local->disconnect();
		exit(0);
	}

	my $query = "SELECT name FROM master..sysdatabases";
	my $sth = $dbh->prepare( $query ) or die "prepare failed\n";
	$sth->execute() or die "unable to execute query $query   error $DBI::errstr\n";

	while( my $results = $sth->fetchrow_arrayref() )
	{
		my $database = $$results[0];
		my $query2 = "SELECT \"TABLE_NAME\",\"COLUMN_NAME\" FROM \"$database\".\"information_schema\".\"columns\"";
		my $sth2 = $dbh->prepare( $query2 ) or die "prepare failed\n";
		$sth2->execute();
		while( my $results2 = $sth2->fetchrow_arrayref() )
		{
			my $table = $$results2[0];
			my $column = $$results2[1];
#			print BLAH "DB: $database\tTable: $table\tColumn: $column\n";
			push @{$data{$database}{$table}}, $column;
		}
		$sth2->finish();
	}
	$sth->finish();

	my $string = "UPDATE systems SET status=1 WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( $tracker );
	$sth_local->finish();

	update_log( "Done enumerating entire database server schema" );
	# figure out what we're going to scan based on policy
	whitelist_schema();
	update_log( "Done whitelisting/blacklisting database server schema...beginning to parse actual data" );

	my $string = "UPDATE systems SET status=?,dbtotal=?,tabletotal=?,columntotal=? WHERE tracker=?";
	my $sth_local = $dbh_local->prepare( $string );
	$sth_local->execute( "2", $total_databases, $total_tables, $total_columns, $tracker );
	$sth_local->finish();


	# grab actual data
	foreach my $db( sort( keys( %whitelist_data )))
	{
		$dbh->do( "use \"$db\"" );
		foreach my $tbl( sort( keys( %{$whitelist_data{$db}} )))
		{
			my $length_col = @{$whitelist_data{$db}{$tbl}};
			if( $length_col > 0 )
			{
				my $select = "SELECT ";
				if( $rows > 0 )
				{
					$select .= "TOP $rows ";
				}
				my $counter = 0;
				foreach my $col( @{$whitelist_data{$db}{$tbl}} )
				{
					$select .= "\"$col\"";
					$counter++;
					if( $counter < $length_col )
					{
						$select .= ",";
					}
				}
#				$select .= " FROM \"$db\".\"$tbl\"";
				$select .= " FROM \"$tbl\"";

				my $sth = $dbh->prepare( $select );
				$sth->execute();

				# microsoft SQL server considers the first row as 1, not 0
				my $row_counter = 1;
				while( my $results = $sth->fetchrow_arrayref() )
				{
					my $col_counter = 0;
					foreach my $coldata( @{$results} )
					{
						my $curr_column = $whitelist_data{$db}{$tbl}[$col_counter];
#						print BLAH "table: $tbl\tcol: $curr_column\tdata: $coldata\n";
						foreach my $key( sort( keys( %regexes )))
						{
							my( $result, $possible_string ) = find_data( $coldata, $key );
							if( $result == 1 )
							{
#								print_log( "PID: $pid || Scanname: $scanname || Target: $target || Tracker: $tracker || DB: $db || Table: $tbl || Col: $curr_column || Row: $row_counter || Pattern: $key || Data: $possible_string\n\n" );
								my $string_copy = "";
								if( $mask == 1 )
								{
									$string_copy = filterme( $possible_string );
								}
								else
								{
									$string_copy = $possible_string;
								}
								my $string = "INSERT INTO results SET scan=?,system=?,type=?,pattern=?,tracker=?,db=?,tbl=?,col=?,row=?,is_false=\"0\"";
								my $sth_local = $dbh_local->prepare( $string );
								$sth_local->execute( $scanname, $target, $key, $string_copy, $tracker, $db, $tbl, $curr_column, $row_counter );
								$sth_local->finish();

							}
						}
						$col_counter++;
					}
					$row_counter++;
				}
				$columns_done += @{$whitelist_data{$db}{$tbl}};
			}
			# update column, table counter in systems table
			$tables_done++;
			my $localtime = time();
			my $update = "UPDATE systems SET tabledone=?,columndone=?,updated=? WHERE tracker=?";
			my $sth_local = $dbh_local->prepare( $update );
			$sth_local->execute( $tables_done, $columns_done, $localtime, $tracker );
			$sth_local->finish();

			update_log( "Done with table \"$tbl\" and $length_col column(s)" );
		}
		# update database counter in systems table
		$databases_done++;
		my $localtime = time();
		my $update = "UPDATE systems SET dbdone=?,updated=? WHERE tracker=?";
		my $sth_local = $dbh_local->prepare( $update );
		$sth_local->execute( $databases_done, $localtime, $tracker );
		$sth_local->finish();

		update_log( "Done with database \"$db\"" );
	}
	$dbh->disconnect();
}

sub find_data
{
	my $coldata = shift;
	my $regex_name = shift;
	my $regex_pattern = $regexes{$regex_name};

	my $possible_find = 0;
	my $is_cc_regex = 0;
	my $found_valid_cc = "";
	my $possible_string = "";
	if( $coldata =~ /($regex_pattern)/ )
	{
		$possible_string = $1;
		$possible_find = 1;
		foreach( @creditcard_array )
		{
			if( $_ eq $regex_name )
			{
				$is_cc_regex = 1;
				my $length_match = length($possible_string);
				my $match_copy = "";
				my $x = 0;
				while( $x < $length_match )
				{
					if( substr( $possible_string, $x, 1 ) =~ /[0-9]/ )
					{
						$match_copy .= substr( $possible_string, $x, 1 );
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
	}

	if( $possible_find == 0 )
	{
		return( 0, "" );
	}
	elsif( $found_valid_cc == 1 )
	{
		return( 1, $possible_string );
	}
	elsif( $is_cc_regex == 1 && $found_valid_cc == 0 )
	{
		return( 0, "" );
	}
	elsif( $is_cc_regex == 0 && $possible_find == 1 )
	{
		return( 1, $possible_string );
	}
	else
	{
		return NULL;
	}
}

sub print_log
{
	my $string = shift;
	open( BLAH, ">>/tmp/blah.txt" );
	print BLAH $string;
	close( BLAH );
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


sub whitelist_schema
{
	foreach my $dbs( sort( keys( %data )))
	{
		if( !is_blacklisted( "db", $dbs ))
		{
			$total_databases++;
			foreach my $tbl( sort( keys( %{$data{$dbs}} )))
			{
				if( !is_blacklisted( "table", $tbl ))
				{
					$total_tables++;
					foreach my $col( @{$data{$dbs}{$tbl}} )
					{
						if( !is_blacklisted( "column", $col ))
						{
							$total_columns++;
							push @{$whitelist_data{$dbs}{$tbl}}, $col;
						}
					}
				}
			}
		}
	}
}

sub is_blacklisted
{
	# ignore, allow, everything
	my $type = shift;
	my $value = shift;

	if( $type eq "db" )
	{
		if( $ignore_dbs eq "everything" )
		{
			return 0;
		}
		elsif( $ignore_dbs eq "ignore" )
		{
			foreach( @db_array )
			{
				if( $_ eq $value )
				{
					return 1;
				}
			}
		}
		elsif( $ignore_dbs eq "allow" )
		{
			my $rc = 1;
			foreach( @db_array )
			{
				if( $_ eq $value )
				{
					$rc = 0;
				}
			}
			return $rc;
		}
	}
	elsif( $type eq "table" )
	{
		if( $ignore_tables eq "everything" )
		{
			return 0;
		}
		elsif( $ignore_tables eq "ignore" )
		{
			foreach( @table_array )
			{
				if( $_ eq $value )
				{
					return 1;
				}
			}
		}
		elsif( $ignore_tables eq "allow" )
		{
			my $rc = 1;
			foreach( @table_array )
			{
				if( $_ eq $value )
				{
					$rc = 0;
				}
			}
			return $rc;
		}
	}
	elsif( $type eq "column" )
	{
		if( $ignore_columns eq "everything" )
		{
			return 0;
		}
		elsif( $ignore_columns eq "ignore" )
		{
			foreach( @column_array )
			{
				if( $_ eq $value )
				{
					return 1;
				}
			}
		}
		elsif( $ignore_columns eq "allow" )
		{
			my $rc = 1;
			foreach( @column_array )
			{
				if( $_ eq $value )
				{
					$rc = 0;
				}
			}
			return $rc;
		}
	}
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
