/*

Copyright Andrew Gavin (andrew.opendlp@gmail.com) 2009-2012

This file is part of OpenDLP.

OpenDLP is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

OpenDLP is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with OpenDLP.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <stdio.h>
#include <strings.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "globals.h"

/* JRS: Included to handle large (>2GB) files */
#if __GNUC__ >=4
#  define stat64 _stati64
#  define fstat64 _fstati64
#else
/* still not right for gcc3.45 */
#  define stat64 stat
#  define fstat64 fstat
#endif

void whitelist()
{
	FILE *allfile;
	FILE *whitelistdir;
	FILE *whitelistfile;
	FILE *log;
	FILE *status_file;
	char allfile_line[MAX_LINE];
	char whitelistdir_line[MAX_LINE];
	char line_file_old[MAX_LINE];
	char line_ext_old[MAX_LINE];
	char whitelistfile_line[MAX_LINE];
	char whitelistfile_backslashes[MAX_LINE];
	char whitelistdir_line_orig[MAX_LINE];
	char* whitelistfile_backslashes_temp;
	char* line_ext;
	char* line_file;
	int found_dir;
	int found_ext;
//	struct stat sb;
	struct stat64 sb;
	unsigned long long file_size = 0;

	WriteToLog( "Beginning to whitelist files\n" );

	/*
	 * Step 1: look for whitelisted/blacklisted directories
	 * Step 2: look for whitelisted/blacklisted file extensions
	 * Step 3: get total file size of remaining files
	 */

	/* Step 1: whitelist/blacklist directories */
	allfile = fopen( ALLDIR, "r" );
	whitelistdir = fopen( WHITELIST_DIR, "a+" );
	WriteToLog( "dir_opt = " );
	WriteToLog( dir_opt );
	WriteToLog( "\n" );

	while( fgets( allfile_line, MAX_LINE, allfile ) != NULL )
	{
		found_dir = 0;
		choppy( allfile_line );
		curr_dir = head_dir;
		while( curr_dir )
		{
			if( !strncasecmp( curr_dir->dir, allfile_line, strlen(curr_dir->dir)) )
			{
				found_dir = 1;
			}
			curr_dir = curr_dir->next;
		}
		if( found_dir == 0 && !strncmp( dir_opt, "ignore", 6 ))
		{
			fprintf( whitelistdir, "%s\n", allfile_line );
		}
		else if( found_dir == 1 && !strncmp( dir_opt, "allow", 5 ))
		{
			fprintf( whitelistdir, "%s\n", allfile_line );
		}
		else if( !strncmp( dir_opt, "everything", 10 ))
		{
			fprintf( whitelistdir, "%s\n", allfile_line );
		}
	}
	fclose( allfile );
	fclose( whitelistdir );
	/* End step 1 */

	/* Step 2: whitelist/blacklist extensions */
	whitelistdir = fopen( WHITELIST_DIR, "r" );
	whitelistfile = fopen( WHITELIST_FILE, "a+" );
	WriteToLog( "ext_opt = " );
	WriteToLog( ext_opt );
	WriteToLog( "\n" );

	while( fgets( whitelistdir_line, MAX_LINE, whitelistdir ) != NULL )
	{
		found_ext = 0;
		choppy( whitelistdir_line );
		strncpy( whitelistdir_line_orig, whitelistdir_line, MAX_LINE );

		line_file = strtok( whitelistdir_line, "\\" );
		while( line_file != NULL )
		{
			strncpy( line_file_old, line_file, MAX_LINE );
			line_file = strtok( NULL, "\\" );
		}

		line_ext = strtok( line_file_old, "." );
		while( line_ext != NULL )
		{
			strncpy( line_ext_old, line_ext, MAX_LINE );
			line_ext = strtok( NULL, "." );
		}
		curr_ext = head_ext;
		while( curr_ext )
		{
			if( !strncasecmp( curr_ext->ext, line_ext_old, strlen(curr_ext->ext)) )
			{
				found_ext = 1;
			}
			curr_ext = curr_ext->next;
		}

		if( found_ext == 0 && !strncmp( ext_opt, "ignore", 6 ))
		{
			fprintf( whitelistfile, "%s\n", whitelistdir_line_orig );
		}

		else if( found_ext == 1 && !strncmp( ext_opt, "allow", 5 ))
		{
			fprintf( whitelistfile, "%s\n", whitelistdir_line_orig );
		}
		else if( !strncmp( ext_opt, "everything", 10 ))
		{
			fprintf( whitelistfile, "%s\n", whitelistdir_line_orig );
		}
	}
	fclose( whitelistdir );
	fclose( whitelistfile );
	/* End step 2 */

	/* Step 3: determine total file size */
	whitelistfile = fopen( WHITELIST_FILE, "r" );
	total_file_size = 0;
	total_files = 0;
	while( fgets( whitelistfile_line, MAX_LINE, whitelistfile ) != NULL )
	{
		choppy( whitelistfile_line );
		whitelistfile_backslashes_temp = strtok( whitelistfile_line, "\\" );
		strcpy( whitelistfile_backslashes, whitelistfile_backslashes_temp );
		whitelistfile_backslashes_temp = strtok( NULL, "\\" );

		while( whitelistfile_backslashes_temp != NULL )
		{
			strcat( whitelistfile_backslashes, "\\\\" );
			strcat( whitelistfile_backslashes, whitelistfile_backslashes_temp );
			whitelistfile_backslashes_temp = strtok( NULL, "\\" );
		}
//		stat( whitelistfile_backslashes, &sb );
		/* JRS: changed to use stat64 rather than stat */
		stat64( whitelistfile_backslashes, &sb );

		file_size = (unsigned long long) sb.st_size;
//		if( file_size > max_memory )
//		{
//			file_size = max_memory;
//		}
		total_file_size += file_size;
		total_files++;

	}
	log = fopen( LOGFILE, "a+" );
	if( log != NULL )
	{
		fprintf( log, "Total number of files to scan: %I64u\n", total_files );
		fprintf( log, "Total bytes of files to scan: %I64u\n", total_file_size );
		fclose( log );
	}
	fclose( whitelistfile );
	/* end Step 3 */

	// upload total files and bytes to scan
	if( upload_stuff( status ) == 0 )
	{
		unlink( LOGFILE );
		WriteToLog( "Successful upload, deleted results and log files\n" );
	}
	else
	{
		WriteToLog( "Upload failed\n" );
	}

	status_file = fopen( STATUS, "w" );
	if( status_file != NULL )
	{
		fprintf( status_file, "2" );
		fclose( status_file );
	}
	status = 2;
	WriteToLog( "Done whitelisting files\n" );
}

