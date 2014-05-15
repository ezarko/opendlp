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
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include "globals.h"

void init_scan()
{
	FILE *log;
	FILE *status_file;
	int config_return;
	char status_string[2];

	if( debug > 0 )
	{
		WriteToLog( "Trying to open config file\n" );
	}

	config_return = read_config();
	if( config_return == -1 )
	{
		exit(-1);
	}

	if( debug > 0 )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "Done reading config file, %i lines read\n", config_return );
			fprintf( log, "Trying to open status file\n" );
			fclose( log );
		}
	}

	log = fopen( LOGFILE, "a+" );
	if( log != NULL )
	{
		fprintf( log, "Log verbosity set to %i\n", debug );
		fclose( log );
	}

	status_file = fopen( STATUS, "r" );
	if( status_file == NULL )
	{
		WriteToLog( "Status file does not exist, assuming status is 0\n" );
		status = 0;
	}
	else
	{
		fgets( status_string, 2, status_file );
		status = atoi( status_string );
		fclose( status_file );
	}

	if( debug > 0 )
	{
		WriteToLog( "Done reading status file\n" );
	}

	log = fopen( LOGFILE, "a+" );
	if( log != NULL )
	{
		fprintf( log, "Status = %i\n", status );
		fclose( log );
	}

	// initialize curl
	if( curl_global_init(CURL_GLOBAL_ALL) != 0 )
	{
		WriteToLog( "*** ERROR: curl_global_init() failed ***\n" );
		exit(0);
	}

	if( debug > 1 )
	{
		WriteToLog( "CURL_GLOBAL_ALL\n" );
	}
}

