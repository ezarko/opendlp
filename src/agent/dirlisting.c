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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include "globals.h"

// WIN32_FIND_DATA *fd;

// int showdir( const char *path );
// int fixpath( const char *inpath, char *outpath );

int showdir( const char *_path )
{
	char command[MAX_LINE];

	command[0] = '\0';
	strcat( command, "dir /B /S /A-D \"" );
	strcat( command, _path );
	strcat( command, "\" >> " );
	strcat( command, ALLDIR );

	system( command );
	return 1;
}

int fixpath( const char *inpath, char *outpath )
{
	int n=0;

	strcpy( outpath, inpath );
	while( inpath[n] ) n++;
	if( inpath[n-1] != '\\' )
	{
		strcat( outpath,"\\" );
		return 1;
	}
	return 0;
}

