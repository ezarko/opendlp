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
#include <strings.h>
#include <unistd.h>
#include <windows.h>
#include <sys/stat.h>
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

int unzip( char filename[MAX_LINE] )
{
	int found_zip = 0;
	int x = 1;
	int remainder = 0;
	int length_ok = 1;
	int zip_error = 0;
	char filename_orig[MAX_LINE];
	char line_file_old[MAX_LINE];
	char line_ext_old[MAX_LINE];
	char unzip_dir[MAX_LINE];
	char unzip_dir_2[MAX_LINE];
	char unzip_contents[MAX_LINE];
	char unzip_contents_line[MAX_LINE];
	char unzip_exe[MAX_LINE];
	char unzip_full_path[MAX_LINE];
	char command[MAX_LINE];
	char temp_buf[32];
	char* line_file;
	char* line_ext;
	char* subject;
	FILE *log;
	FILE *unzip_out;
	FILE *unzip_file;
	unsigned long long subject_length;
	unsigned long long number_of_chunks;
	unsigned long long chunk_counter;

	/* JRS: Added to handle large (>2GB) files */
	struct stat64 file_size = { 0 };

	strncpy( filename_orig, filename, MAX_LINE );

	// fix this so it only tokenizes by \\, not \\\\ ?
	line_file = strtok( filename, "\\\\" );
	while( line_file != NULL )
	{
		strncpy( line_file_old, line_file, MAX_LINE );
		line_file = strtok( NULL, "\\\\" );
	}

	line_ext = strtok( line_file_old, "." );
	while( line_ext != NULL )
	{
		strncpy( line_ext_old, line_ext, MAX_LINE );
		line_ext = strtok( NULL, "." );
	}
	curr_zip = head_zip;
	while( curr_zip )
	{
		if( !strncasecmp( curr_zip->zip, line_ext_old, strlen(curr_zip->zip)) )
		{
			found_zip = 1;
		}
		curr_zip = curr_zip->next;
	}

	if( found_zip == 1 )
	{
		if( debug > 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Found zip file %s\n", filename_orig );
				fclose( log );
			}
		}

		unzip_exe[0] = '\0';
		remainder = MAX_PATH - strlen(homedir) - strlen("unzip.exe") - 1;
		if( remainder > 0 )
		{
			strcat( unzip_exe, homedir );
			strcat( unzip_exe, "unzip.exe" );
		}
		else
		{
			WriteToLog( "Length of path for unzip.exe is too long.\n" );
			return -1;
		}

		strncpy( unzip_dir, homedir, MAX_PATH );
		remainder = MAX_PATH - strlen(unzip_dir) - 1;
		if( remainder >= 2 )
		{
			strncat( unzip_dir, "1\\", 2 );
		}
		else
		{
			WriteToLog( "Length of path for ZIP file\'s content listing is too long.\n" );
			return -1;
		}

		while( mkdir( unzip_dir ) != 0 )
		{
			x++;
			strncpy( unzip_dir, homedir, MAX_PATH );
			remainder = MAX_PATH - strlen(unzip_dir) - 1;
			snprintf( temp_buf, sizeof(temp_buf), "%i", x );

			if( remainder >= strlen(temp_buf) )
			{
				if( debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Appending %s (int is %i) to unzip dir\n", temp_buf, x );
						fclose( log );
					}
				}
	
				strncat( unzip_dir, temp_buf, strlen(temp_buf) );
				strncat( unzip_dir, "\\", 1 );
			}
			else
			{
				WriteToLog( "Length of unzip path is too long.\n" );
				return -1;
			}

			if( debug > 1 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "unzip: Checking if %s is available\n", unzip_dir );
					fclose( log );
				}
			}
		}

		unzip_contents[0] = '\0';
		remainder = MAX_PATH - strlen(unzip_dir) - 2;
		if( remainder > 0 )
		{
			strcat( unzip_contents, unzip_dir );
			strcat( unzip_contents, "c" );
		}
		else
		{
			WriteToLog( "Length of unzip path is too long.\n" );
			return -1;
		}

		// unzip.exe -Z -1 file.zip > unzip_dir\c
		command[0] = '\0';
		strcat( command, "unzip.exe -Z -1 \"" );
		strcat( command, filename_orig );
		strcat( command, "\" > \"" );
		strcat( command, unzip_contents );
		strcat( command, "\"" );

		if( debug > 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Running %s\n", command );
				fclose( log );
			}
		}

		system( command );

		if( debug > 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Done listing contents of zip file\n" );
				fclose( log );
			}
		}


		// check length of each file to ensure "homedir" + "strlen(each file)" < MAX_PATH
		unzip_out = fopen( unzip_contents, "r" );
		if( unzip_out != NULL )
		{
			while( fgets( unzip_contents_line, MAX_LINE, unzip_out ) != NULL )
			{
				choppy( unzip_contents_line );
				if( (strlen(unzip_dir) + strlen(unzip_contents_line) + 1) > MAX_PATH )
				{
					length_ok = 0;
				}
			}
			fclose( unzip_out );
		}

		// if all files pass:
		if( length_ok )
		{
			if( debug > 0 )
			{
				WriteToLog( "Lengths of all files inside ZIP are ok\n" );
			}

			// 1. unzip.exe file.zip -d unzip_dir+1
			// 1a. build directory where contents of ZIP will go
			x++;
			strncpy( unzip_dir_2, homedir, MAX_PATH );
			snprintf( temp_buf, sizeof(temp_buf), "%i", x );
			remainder = MAX_PATH - strlen(unzip_dir_2) - strlen(temp_buf);
			if( remainder >= 2 )
			{
				if( debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Appending %s (int is %i) to unzip dir\n", temp_buf, x );
						fclose( log );
					}
				}
	
				strncat( unzip_dir_2, temp_buf, strlen(temp_buf) );
				strncat( unzip_dir_2, "\\", 1 );
			}
			else
			{
				WriteToLog( "Length of directory for unzip contents is too long\n" );
				return -1;
			}

			while( mkdir( unzip_dir_2 ) != 0 )
			{
				x++;
				strncpy( unzip_dir_2, homedir, MAX_PATH );
				remainder = MAX_PATH - strlen(unzip_dir_2) - 1;
				snprintf( temp_buf, sizeof(temp_buf), "%i", x );

				if( remainder >= strlen(temp_buf) )
				{
					if( debug > 1 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Appending %s (int is %i) to unzip dir\n", temp_buf, x );
							fclose( log );
						}
					}
	
					strncat( unzip_dir_2, temp_buf, strlen(temp_buf) );
					strncat( unzip_dir_2, "\\", 1 );
				}
				else
				{
					WriteToLog( "Length of directory for unzip contents is too long\n" );
					return -1;
				}

				if( debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "unzip: Checking if %s is available\n", unzip_dir_2 );
						fclose( log );
					}
				}
			}

			command[0] = '\0';
			strcat( command, "unzip.exe -n -P \"\" \"" );
			strcat( command, filename_orig );
			strcat( command, "\" -d " );
			strcat( command, temp_buf );
//			strcat( command, "\" -d \"" );
//			strcat( command, unzip_dir_2 );
//			strcat( command, "\"" );

			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Found ZIP, running: %s\n", command );
				fclose( log );
			}
			system( command );

			// 2. for each file in unzip_contents
			unzip_out = fopen( unzip_contents, "r" );
			while( fgets( unzip_contents_line, MAX_LINE, unzip_out ) != NULL )
			{
				choppy( unzip_contents_line );

				// 2a. Replace '/' with '\'
				replace_char( unzip_contents_line, '/', '\\' );

				// 2b. Prepend unzip_dir_2 to path
				unzip_full_path[0] = '\0';
				strcat( unzip_full_path, unzip_dir_2 );
				strcat( unzip_full_path, unzip_contents_line );

				// 2c. read file
				unzip_file = fopen( unzip_full_path, "rb" );
				if( debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Processing file %s\n", unzip_full_path );
						fclose( log );
					}
				}

				while( unzip_file == NULL )
				{
					if( debug > 0 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Cannot open file %s inside ZIP %s, skipping it.\n", unzip_contents_line, filename_orig );
							fclose( log );
						}
					}

					if( fgets( unzip_contents_line, MAX_LINE, unzip_out ) == NULL )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Could not open last item in zip file contents, or there was an error processing zip file. Stopping the processing of this zip file.\n" );
							fclose( log );
						}
						zip_error = 1;
						break;
					}
					else
					{
						choppy( unzip_contents_line );
						replace_char( unzip_contents_line, '/', '\\' );
						unzip_full_path[0] = '\0';
						strcat( unzip_full_path, unzip_dir_2 );
						strcat( unzip_full_path, unzip_contents_line );

						if( debug > 1 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Starting to process file %s\n", unzip_full_path );
								fclose( log );
							}
						}
					}
				}
				if( unzip_file != NULL )
				{
					fclose( unzip_file );
				}

				if( zip_error == 0 )
				{
					/* JRS: Changed to handle large (>2GB) files
					 * unzip_file = fopen( unzip_full_path, "rb" );
					 * fseek( unzip_file, 0, SEEK_END );
					 * subject_length = ftell( unzip_file );
					 * rewind( unzip_file );
					 */

					stat64( unzip_full_path, &file_size );
					subject_length = (unsigned long long) file_size.st_size;
					fclose( unzip_file );

					number_of_chunks = (subject_length / max_memory) + 1;
					if( number_of_chunks > 1 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "%s is too big (%I64u bytes), chopping into %I64u chunks\n", unzip_full_path, subject_length, number_of_chunks );
							fclose( log );
						}
					}

					chunk_counter = 0;
					while( chunk_counter < number_of_chunks )
					{
						unzip_file = fopen( unzip_full_path, "rb" );
						fseek( unzip_file, chunk_counter * max_memory, SEEK_SET );
						if( chunk_counter == (number_of_chunks - 1) )
						{
							subject = calloc( (subject_length % max_memory), sizeof( char ));
							if( subject == NULL )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Cannot allocate memory for zip file chunk for file %s\n", unzip_contents_line );
									fclose( log );
								}
								break;
							}

							int ret = fread( subject, 1, (subject_length % max_memory), unzip_file );
							if( ret <= 0 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Cannot copy contents from zip file %s into allocated memory\n", unzip_contents_line );
									fclose( log );
								}
								break;
							}

							do_regex( subject, (subject_length % max_memory), filename_orig, unzip_contents_line, chunk_counter );
						}
						else
						{
							subject = calloc( max_memory, sizeof( char ));
							if( subject == NULL )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Cannot allocate memory for zip file chunk for file %s\n", unzip_contents_line );
									fclose( log );
								}
								break;
							}

							int ret = fread( subject, 1, max_memory, unzip_file );
							if( ret <= 0 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Cannot copy contents from zip file %s into allocated memory\n", unzip_contents_line );
									fclose( log );
								}
								break;
							}

							do_regex( subject, max_memory, filename_orig, unzip_contents_line, chunk_counter );
						}

						if( subject != NULL )
						{
							free(subject);
						}

						if( unzip_file != NULL )
						{
							fclose( unzip_file );
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
				}
				// 2f. set it read/write so we can delete it
				chmod( unzip_full_path, 666 );

				// 2g. delete file from disk
				unlink( unzip_full_path );
				if( debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Deleted file %s\n", unzip_full_path );
						fclose( log );
					}
				}
			}

			if( unzip_out != NULL )
			{
				fclose( unzip_out );
			}

			// Delete everything zip-related
			unlink( unzip_contents );
			if( debug > 1 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Attempting to recursively delete directory %s\n", unzip_dir );
					fclose( log );
				}
			}
			deletedir( unzip_dir );

			if( fd != NULL )
			{
				free(fd);
			}

			if( debug > 1 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Attempting to recursively delete directory %s\n", unzip_dir_2 );
					fclose( log );
				}
			}
			deletedir( unzip_dir_2 );
			if( fd != NULL )
			{
				free(fd);
			}
			rmdir( unzip_dir );
			rmdir( unzip_dir_2 );
		}

		// length not ok
		else
		{
			WriteToLog( "Length of path for file inside ZIP is too long. Not unzipping.\n" );
			unlink( unzip_contents );
			rmdir( unzip_dir );
			return -1;
		}
	}
	return 0;
}

int deletedir( const char *_path )
{
	HANDLE fh;
	FILE* log;
	int filecnt=0;
	char tmppath[MAX_PATH];
	char path[MAX_PATH];

	fd = malloc( sizeof(WIN32_FIND_DATA) );
	if( fd == NULL )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "Cannot allocate memory to delete directory\n" );
			fclose( log );
		}
		return 0;
	}
	fixpath( _path, path );
	strcat( path, "*" );
	fh = FindFirstFile( (LPCSTR) path, fd );

	if( fh != INVALID_HANDLE_VALUE )
	{
		do
		{
			filecnt++;
			if( fd->dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
			{
				if(( 0 != strcmp( fd->cFileName, "." )) && ( 0 != strcmp( fd->cFileName, ".." )))
			        {
					fixpath( _path, tmppath );
					strcat( tmppath, fd->cFileName );
					fixpath( tmppath, tmppath );
					deletedir( tmppath );
					if( debug > 1 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Attempting to delete DIRECTORY %s\n", tmppath );
							fclose( log );
						}
					}
					rmdir( tmppath );
				}
			}
			else
			{
				fixpath( _path, tmppath );
				strcat( tmppath, fd->cFileName );
				if( debug > 1 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Attempting to delete FILE %s\n", tmppath );
						fclose( log );
					}
				}
				unlink( tmppath );
			}
		}
		while( FindNextFile(fh,fd) );
	}
	FindClose( fh );
	return 1;
}

