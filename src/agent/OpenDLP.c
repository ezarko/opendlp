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

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
//#include <assert.h>
//#include <sys/types.h>
//#include <sys/stat.h>
//#include <pcre.h>
//#include <time.h>
//#include <curl/curl.h>
//#include <curl/types.h>
//#include <curl/easy.h>
#include "globals.h"

int main( int argc, char **argv )
{
	FILE *log;
	int homedir_temp_counter = 0;
	int homedir_temp_counter_2 = 0;
	char *homedir_temp;
	char argv_copy[MAX_LINE];

	if( strlen( argv[0] ) >= MAX_LINE )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "Command line argument too long, quitting...\n" );
			fclose( log );
			exit( -1 );
		}
	}

	strncpy( argv_copy, argv[0], strlen(argv[0]) );
	homedir_temp = strtok( argv[0], "\\" );
	while( homedir_temp != NULL )
	{
		homedir_temp_counter++;
		homedir_temp = strtok( NULL, "\\" );
	}

	homedir_temp = strtok( argv_copy, "\\" );
	while( homedir_temp_counter_2 < (homedir_temp_counter - 1) )
	{
		strcat( homedir, homedir_temp );
		strcat( homedir, "\\" );
		homedir_temp = strtok( NULL, "\\" );
		homedir_temp_counter_2++;
	}

	SetPriorityClass( GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS );

	SetCurrentDirectory( homedir );
	log = fopen( LOGFILE, "a+" );
	if( log != NULL )
	{
		fprintf( log, "SetCurrentDirectory = %s\n", homedir );
		fclose( log );
	}

	SERVICE_TABLE_ENTRY ServiceTable[2];
	ServiceTable[0].lpServiceName = "MemoryStatus";
	ServiceTable[0].lpServiceProc = (LPSERVICE_MAIN_FUNCTION)ServiceMain;

	ServiceTable[1].lpServiceName = NULL;
	ServiceTable[1].lpServiceProc = NULL;
	// Start the control dispatcher thread for our service
	StartServiceCtrlDispatcher(ServiceTable);
	return 1;
}

/* meat and potatoes */
void ServiceMain(int argc, char** argv) 
{ 
	int error;
	FILE* log;

	ServiceStatus.dwServiceType = SERVICE_WIN32;
	ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
	ServiceStatus.dwWin32ExitCode = 0;
	ServiceStatus.dwServiceSpecificExitCode = 0;
	ServiceStatus.dwCheckPoint = 0;
	ServiceStatus.dwWaitHint = 0; 

	hStatus = RegisterServiceCtrlHandler( "MemoryStatus", (LPHANDLER_FUNCTION)ControlHandler);
	if (hStatus == (SERVICE_STATUS_HANDLE)0)
	{
		// Registering Control Handler failed
		return;
	}
	// Initialize Service
	error = InitService();
	if (error)
	{
		// Initialization failed
		ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		ServiceStatus.dwWin32ExitCode = -1;
		SetServiceStatus(hStatus, &ServiceStatus);
		return;
	}

	// We report the running status to SCM.
	ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	SetServiceStatus (hStatus, &ServiceStatus);

	// The worker loop of a service
	while (ServiceStatus.dwCurrentState == SERVICE_RUNNING)
	{
		status = -1;
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "Status = %i\n", status );
			fclose( log );
		}

		// status is -1 at start, so every time this runs, force it to read config and status file
		if( status < 0 || status > 3 )
		{
			init_scan();
		}

		// perform recursive directory listing
		if( status == 0 )
		{
			recurse_all_dirs();
		}

		// whitelist files based on policy, sum file sizes and number of files
		if( status == 1 )
		{
			whitelist();
		}

		// grep for stuff
		if( status == 2 )
		{
			search();
		}

		// we are all done
		if( status == 3 )
		{
			int upload_attempt = 1;
			WriteToLog( "Done with everything. Sending request to web server to uninstall us.\n" );

			while( upload_stuff( status ) != 0 )
			{
				upload_attempt++;
				Sleep( time_wait * 1000 );
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Done with everything. Sending request #%i to web server to uninstall us.\n", upload_attempt );
					fclose( log );
				}
			}
		}
	}
	return;
}

// Service initialization
int InitService()
{
	int result;
	result = WriteToLog("OpenDLP service started.\n");
	return(result);
}

void ControlHandler(DWORD request)
{
	switch(request)
	{
		case SERVICE_CONTROL_STOP:
			WriteToLog("OpenDLP service stopped.\n");

			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus (hStatus, &ServiceStatus);
			return;
 
		case SERVICE_CONTROL_SHUTDOWN:
			WriteToLog("Monitoring service stopped.\n");

			ServiceStatus.dwWin32ExitCode = 0;
			ServiceStatus.dwCurrentState = SERVICE_STOPPED;
			SetServiceStatus (hStatus, &ServiceStatus);
			return;

		default:
			break;
	}
 
	// Report current status
	SetServiceStatus (hStatus, &ServiceStatus);

	return;
}

int WriteToLog(char* str)
{
	FILE* log;
	log = fopen(LOGFILE, "a+");
	if (log == NULL)
	{
		return -1;
	}
	fprintf(log, "%s", str);
	fclose(log);
	return 0;
}

void choppy( char *s )
{
	s[strcspn( s, "\n" )] = '\0';
}

void replace_char( char *s, char find, char replace )
{
	while (*s != 0)
	{
		if (*s == find)
		{
			*s = replace;
		}
		s++;
	}
}

