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
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "globals.h"

/* JRS: Included to handle large (>2GB) files */
#include <sys/stat.h>

#if __GNUC__ >=4
#  define stat64 _stati64
#  define fstat64 _fstati64
#else
/* still not right for gcc3.45 */
#  define stat64 stat
#  define fstat64 fstat
#endif

void search()
{
	FILE *counter;
	FILE *log;
	FILE *whitelistfile;
	FILE *wl_file;
	FILE *status_file;
	FILE* bytes_file;
	time_t time_start;
	time_t time_stop;
	char bytes_string[32];
	char file_number_line[64];
	char whitelistfile_line[MAX_LINE];
	char* subject;
	unsigned long long subject_length;
	unsigned long long file_number_counter = 0;
	unsigned long long seek_end;
	unsigned long long number_of_chunks;
	unsigned long long chunk_counter;
	int have_md5;
	int unzip_ret;

	/* JRS: Added to handle large (>2GB) files */
	struct stat64 file_size = { 0 };

	if( !access( ALLDIR, F_OK ))
	{
		unlink( ALLDIR );
	}
	if( !access( WHITELIST_DIR, F_OK ))
	{
		unlink( WHITELIST_DIR );
	}

	time_start = time( NULL );
	WriteToLog( "Beginning to grep stuff\n" );

	// get file counter
	counter = fopen( COUNTER, "r" );
	if( counter != NULL )
	{
		fgets( file_number_line, 64, counter );
		file_number = atoll( file_number_line );
		fclose( counter );
	}
	else
	{
		file_number = 0;
	}

	log = fopen( LOGFILE, "a+" );
	if( log != NULL )
	{
		if( file_number > 0 )
		{
			fprintf( log, "Resuming with file %I64u\n", file_number );
		}
		fclose( log );
	}

	whitelistfile = fopen( WHITELIST_FILE, "r" );

	/* read and open each file in the whitelist */
	while( fgets( whitelistfile_line, MAX_LINE, whitelistfile ) != NULL )
	{
		while( file_number_counter < file_number )
		{
			fgets( whitelistfile_line, MAX_LINE, whitelistfile );
			file_number_counter++;
		}

		choppy( whitelistfile_line );
		wl_file = fopen( whitelistfile_line, "rb" );
		/* if the open fails, keep looping until we get a successful open */
		while( wl_file == NULL )
		{
			file_number++;
			file_number_counter++;

			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Cannot open %s\nSkipping to next file\n", whitelistfile_line );
				fclose( log );
			}

			if( fgets( whitelistfile_line, MAX_LINE, whitelistfile ) == NULL )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "whitelistfile_line is NULL, we must be at EOF, setting status to 3\n" );
					fclose( log );
				}
				status = 3;
				break;
			}
			else
			{
				choppy( whitelistfile_line );
				wl_file = fopen( whitelistfile_line, "rb" );
			}
		}

		if( status == 2 )
		{
			have_md5 = 0;

			/* JRS: Changed to handle large (>2GB) files 
			 * fseek( wl_file, 0, SEEK_END );
			 * seek_end = ftell( wl_file );
			 * subject_length = seek_end;
			 * rewind( wl_file );
			 */

			/* JRS: Use the new method */
			stat64( whitelistfile_line, &file_size );
			seek_end = (unsigned long long) file_size.st_size;
			subject_length = seek_end;
			fclose( wl_file );

			if( debug > 1 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Starting to process file %s\n", whitelistfile_line );
					fclose( log );
				}
			}

			// limit reading to max_memory chunks of bytes
			number_of_chunks = (seek_end / max_memory) + 1;
			if( number_of_chunks > 1 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "%s is too big (%I64u bytes), chopping into %I64u chunks\n", whitelistfile_line, seek_end, number_of_chunks );
					fclose( log );
				}
			}


			chunk_counter = 0;
			while( chunk_counter < number_of_chunks )
			{
				wl_file = fopen( whitelistfile_line, "rb" );
				fseek( wl_file, chunk_counter * max_memory, SEEK_SET );
				if( chunk_counter == (number_of_chunks - 1) )
				{
					subject = calloc( (subject_length % max_memory), sizeof(char) );
					if( subject == NULL )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Cannot allocate memory for file chunk for file %s\n", whitelistfile_line );
							fclose( log );
						}
						break;
					}

					int ret = fread( subject, 1, (subject_length % max_memory), wl_file );
					if( ret < 0 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Cannot copy contents from file %s into allocated memory\n", whitelistfile_line );
							fclose( log );
						}
						break;
					}
					do_regex( subject, (subject_length % max_memory), whitelistfile_line, NULL, chunk_counter );
				}
				else
				{
					subject = calloc( max_memory, sizeof( char ));
					if( subject == NULL )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Cannot allocate memory for file chunk for file %s\n", whitelistfile_line );
							fclose( log );
						}
						break;
					}

					int ret = fread( subject, 1, max_memory, wl_file );
					if( ret < 0 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Cannot copy contents from file %s into allocated memory\n", whitelistfile_line );
							fclose( log );
						}
						break;
					}

					do_regex( subject, max_memory, whitelistfile_line, NULL, chunk_counter );
				}
				if( subject != NULL )
				{
					free( subject );
				}
				if( wl_file != NULL )
				{
					fclose( wl_file );
				}
				chunk_counter++;
				if( number_of_chunks > 1 && debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Done with chunk %I64u of %I64u\n", chunk_counter, number_of_chunks );
						fclose( log );
					}
				}
			}

			// see if file is a zip
			unzip_ret = unzip( whitelistfile_line );
			if( unzip_ret != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Could not unzip %s\n", whitelistfile_line );
					fclose( log );
				}
			}

			file_number++;
			file_number_counter++;
			counter = fopen( COUNTER, "w" );
			if( counter != NULL )
			{
				fprintf( counter, "%I64u", file_number );
				fclose( counter );
			}

			/* update bytes processed */
			bytes_file = fopen( BYTES, "r" );
			if( bytes_file == NULL )
			{
				WriteToLog( "Bytes file does not exist, assuming bytes = 0\n" );
				bytes_processed = subject_length;
				bytes_file = fopen( BYTES, "w" );
				if( bytes_file != NULL )
				{
					fprintf( bytes_file, "%I64u", subject_length );
					fclose( bytes_file );
				}
			}
			else
			{
				fgets( bytes_string, 32, bytes_file );
				bytes_processed = atoll( bytes_string );
				bytes_processed += subject_length;
				if( bytes_file != NULL )
				{
					fclose( bytes_file );
				}
				bytes_file = fopen( BYTES, "w" );
				if( bytes_file != NULL )
				{
					fprintf( bytes_file, "%I64u", bytes_processed );
					fclose( bytes_file );
				}
			}

			/* log every 500 files we've grepped */
			if( file_number % 500 == 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Processed file %I64u\n", file_number );
					fclose( log );
				}
			}

			/* upload results every X seconds */
			time_stop = time( NULL );
			if( (time_stop - time_start) > time_wait )
			{
				WriteToLog( "Attempting to upload stuff now\n" );

				if( upload_stuff( status ) == 0 )
				{
					unlink( RESULTS );
					unlink( LOGFILE );

					WriteToLog( "Successful upload, deleted results and log files\n" );
				}
				else
				{
					WriteToLog( "Upload failed\n" );
				}

				time_start = time( NULL );
			}
		}
	}

	if( whitelistfile != NULL )
	{
		fclose( whitelistfile );
	}

	WriteToLog( "Done grepping stuff\n" );

	status_file = fopen( STATUS, "w" );
	if( status_file != NULL )
	{
		fprintf( status_file, "3" );
		fclose( status_file );
	}

	status = 3;
}

