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
#include <string.h>
#include "globals.h"

int mod10( char *cc )
{
	char cc_copy[19];
	int k = 0;
	int j = 0;
	FILE* log;
	int n, alternate, sum, i;


	for( k = 0; k < strlen(cc); k++ )
	{
		if( cc[k] >= '\x30' && cc[k] <= '\x39' )
		{
			cc_copy[j] = cc[k];
			j++;
		}
	}
	cc_copy[j] = '\x00';

	n = strlen( cc_copy );
	for( alternate = 0, sum = 0, i = n - 1; i > -1; --i )
	{
		n = cc_copy[i] - '0';
		if( alternate )
		{
			n *= 2;
			if( n > 9 )
			{
				n = (n % 10) + 1;
			}
		}
		alternate = !alternate;
		sum += n;
	}
	if( sum % 10 == 0 )
	{
		return 1;
	}
	else
	{
		return -1;
	}
}

