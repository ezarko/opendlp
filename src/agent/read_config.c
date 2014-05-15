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
#define _WIN32_WINNT 0x0500

#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <windows.h>
#include "globals.h"

int read_config()
{
	FILE* config;
	FILE* log;
	char input[MAX_LINE];
	char* token;
	char* value;
	int lines_read = 0;

	head_ext = NULL;
	head_zip = NULL;
	head_dir = NULL;
	head_regex = NULL;
	head_cc = NULL;

	config = fopen( CONFIG, "r" );
	if( config == NULL )
	{
		WriteToLog( "Cannot read config file, aborting...\n" );
		return -1;
	}

	while( fgets( input, MAX_LINE, config ) != NULL )
	{
		lines_read++;
		if( strncmp( input, "#", 1 ) && strncmp( input, "\n", 1 ))
		{
			token = strtok( input, "=" );
			if( !strncmp( token, "ext_opt", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( ext_opt, value, 16 );
			}
			else if( !strncmp( token, "wait", 4 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				time_wait = atoi( value );
			}
			else if( !strncmp( token, "ext", 3 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				curr_ext = (exts *)malloc( sizeof( exts ));
				strncpy( curr_ext->ext, value, MAX_LINE);
				curr_ext->next = head_ext;
				head_ext = curr_ext;
							}
			else if( !strncmp( token, "dir_opt", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( dir_opt, value, 16 );
			}
			else if( !strncmp( token, "dir", 3 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				curr_dir = (dirs *)malloc( sizeof( dirs ));
				if( !strncasecmp( value, "\%OPENDLP\%", 9 ))
				{
					strncpy( curr_dir->dir, homedir, MAX_LINE );
				}
				else
				{
					strncpy( curr_dir->dir, value, MAX_LINE );
				}
				curr_dir->next = head_dir;
				head_dir = curr_dir;
			}
			else if( !strncmp( token, "regex", 5 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				curr_regex = (regex *)malloc( sizeof( regex ));
				strncpy( curr_regex->regex_name, strtok( value, ":" ), 128 );
				strncpy( curr_regex->regex_value, strtok( NULL, "\0" ), 2048 );
				curr_regex->next = head_regex;
				head_regex = curr_regex;
			}
			else if( !strncmp( token, "creditcard", 10 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				curr_cc = (cc *)malloc( sizeof( cc ));
				strncpy( curr_cc->cc_name, value, 128 );
				curr_cc->next = head_cc;
				head_cc = curr_cc;
							}
			else if( !strncmp( token, "uploadurl", 9 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( url, value, 255 );
			}
			else if( !strncmp( token, "urluser", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( urluser, value, 32 );
			}
			else if( !strncmp( token, "urlpass", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( urlpass, value, 32 );
			}
			else if( !strncmp( token, "debug", 5 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				debug = atoi( value );
			}
			else if( !strncmp( token, "tracker", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( tracker, value, 32 );
			}
			else if( !strncmp( token, "scan", 4 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( scan, value, 65 );
			}
			else if( !strncmp( token, "profile", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				strncpy( profile, value, 65 );
			}
			else if( !strncmp( token, "zipfile", 7 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );
				curr_zip = (zips *)malloc( sizeof( zips ));
				strncpy( curr_zip->zip, value, MAX_LINE);
				curr_zip->next = head_zip;
				head_zip = curr_zip;
			}
			else if( !strncmp( token, "memory", 6 ))
			{
				value = strtok( NULL, "\0" );
				choppy( value );

				MEMORYSTATUSEX memory;
				memory.dwLength = sizeof( memory );
				GlobalMemoryStatusEx( &memory );

				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Available physical memory: %I64u bytes\n", memory.ullTotalPhys );
					fclose( log );
				}
				max_memory = atof( value ) * memory.ullTotalPhys;
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Limiting maximum memory usage to %I64u bytes\n", max_memory );
					fclose( log );
				}
			}
		}
	}
	fclose( config );
	return lines_read;
}
