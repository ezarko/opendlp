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

#include <unistd.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "globals.h"

void recurse_all_dirs()
{
	int drive_type;
	char *pch;
	char drives[1024];
	FILE *log;
	FILE *status_file;

	// tell server that file enumeration is starting
	if( upload_stuff( status ) == 0 )
	{
		unlink( LOGFILE );
		WriteToLog( "Successful upload, deleted results and log files\n" );
	}
	else
	{
		WriteToLog( "Upload failed\n" );
	}

	if( !access( ALLDIR, F_OK ))
	{
		unlink( ALLDIR );
	}

	// get all dirs/files if policy is not "allow"
	if( strncmp( dir_opt, "allow", 5 ))
		{
		GetLogicalDriveStrings( 1024, drives );
		pch = drives;
		while( *pch )
		{
			drive_type = GetDriveType( pch );

			// drive_type 2 = floppy, thumb drive, flash card reader
			// drive_type 3 = HDD, flash drive
			// drive_type 4 = network drive
			// drive_type 5 = CD-ROM
			// drive_type 6 = RAM disk
			if( drive_type == 3 || drive_type == 5 || drive_type == 6 )
			{
				// recursively list contents of drive
				log = fopen(LOGFILE, "a+");
				if( log != NULL )
				{
					fprintf(log, "Drive %s is of type %i, so I will scan it\n", pch, drive_type);
					fclose(log);
				}
				showdir( pch );
			}
			else
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Drive %s is of type %i, so I will ignore it\n", pch, drive_type );
					fclose( log );
				}
			}
			pch = &pch[strlen(pch) + 1];
		}
		WriteToLog( "Done scanning for drives\n" );
	}
	else if( !strncmp( dir_opt, "allow", 5 ))
	{
		curr_dir = head_dir;
		while( curr_dir )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Enumerating contents of directory \"%s\"\n", curr_dir->dir );
				fclose( log );
			}
			showdir( curr_dir->dir );
			curr_dir = curr_dir->next;
		}
	}

	status_file = fopen( STATUS, "w" );
	if( status_file != NULL )
	{
		fprintf( status_file, "1" );
		fclose( status_file );
	}

	status = 1;
}

