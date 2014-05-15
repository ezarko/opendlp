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

#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include "md5.h"
#include "globals.h"

void do_regex( char *subject, unsigned long long subject_length, char *whitelistfile_backslashes, char *compressedfile_backslashes, unsigned long long chunk_counter )
{
	pcre *re = NULL;
	const char *pcre_error;
	int OVECCOUNT = 30;
	int erroffset;
	int ovector[OVECCOUNT];
	int offset = 0;
	char *ptr;
	char *result = NULL;
	char *result_copy = NULL;
	int diff;
	FILE* results;
	FILE* log;
	int line;
	unsigned long long file_offset = 0;
	int rc;
	int i = 0;
	int found_possible_cc = 0;
	int found_something_good = 0;
	int have_md5 = 0;
	int md5count = 0;
	struct MD5Context md5c;
	unsigned char md5sig[16];

	curr_regex = head_regex;
	/* loop through each regex */
	while(curr_regex)
	{
		file_offset = 0;
		re = pcre_compile( curr_regex->regex_value, PCRE_MULTILINE, &pcre_error, &erroffset, NULL );
		if( re == NULL )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "PCRE compilation failed at offset %d: %s\n", erroffset, pcre_error );
				fclose( log );
			}
		}
		else
		{
			if( debug > 1 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "Compiled regex %s\n", curr_regex->regex_name );
					fclose( log );
				}
			}

			rc = pcre_exec( re, NULL, subject, subject_length, 0, 0, ovector, OVECCOUNT );

			// no match
			if( rc < 0 )
			{
				if( debug > 2 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "No match for regex %s\n", curr_regex->regex_name );
						fclose( log );
					}
				}
				if( re != NULL )
				{
					free( re );
					re = NULL;
				}
			}

			// we have a match
			else
			{
				if( debug > 2 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Found potential match in first regex loop for regex %s\n", curr_regex->regex_name );
						fclose( log );
					}
				}
				if( rc == 0 )
				{
					rc = OVECCOUNT/3;
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "ovector only has room for %d captured substrings\n", rc - 1);
						fclose( log );
					}
				}

				file_offset = ovector[0];
				char *substring_start = subject + ovector[0];
				int substring_length = ovector[1] - ovector[0];
				result = calloc( substring_length + 1, sizeof( char ));
				if( result == NULL )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "First calloc() failed in first regex loop. Breaking out of while() loop for regex %s\n", curr_regex->regex_name );
						fclose( log );
					}
					if( re != NULL )
					{
						free( re );
						re = NULL;
					}
					break;
				}
				else
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "First calloc() succeeded in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}

				result_copy = calloc( substring_length + 1, sizeof( char ));
				if( result_copy == NULL )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Second calloc() failed in first regex loop. Breaking out of while() loop for regex %s\n", curr_regex->regex_name );
						fclose( log );
					}
					if( result != NULL )
					{
						free( result );
						result = NULL;
					}
					if( re != NULL )
					{
						free( re );
						re = NULL;
					}
					break;
				}
				else
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Second calloc() succeeded in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}

				// using memcpy instead of strncpy because of embedded NULLs
				memcpy( result, substring_start, substring_length );
				memcpy( result_copy, substring_start, substring_length );
				if( debug > 2 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "memcpy() succeeded in first regex loop for %s\n", curr_regex->regex_name );
						fclose( log );
					}
				}

				for( i = 0; i < (ovector[1] - ovector[0]); i++ )
				{
					if( result[i] == '\x0a' || result[i] == '\x00' || result[i] == '\x0d' )
					{
						result[i] = '\x3f';
						result_copy[i] = '\x3f';
					}
				}

				result[substring_length] = '\x00';
				result_copy[substring_length] = '\x00';

				if( debug > 2 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "characters replaced and NULL-terminated in first regex loop for %s\n", curr_regex->regex_name );
						fclose( log );
					}
				}

				found_possible_cc = 0;
				found_something_good = 0;
				curr_cc = head_cc;
				while( curr_cc )
				{
					if( !strcmp( curr_cc->cc_name, curr_regex->regex_name ))
					{
						found_possible_cc = 1;
					}
					curr_cc = curr_cc->next;
				}

				if( found_possible_cc == 1 )
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Trying mod10 check in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}

					found_something_good = mod10( result_copy );

					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Done with mod10 check in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}
				else
				{
					found_something_good = 1;
				}

				if( debug > 2 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Attempting to free \"result_copy\" in first regex loop for %s\n", curr_regex->regex_name );
						fclose( log );
					}
				}

				if( result_copy != NULL )
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "\"result_copy\" is not NULL in first regex loop for %s, it is: %s\n", curr_regex->regex_name, result_copy );
							fclose( log );
						}
					}
					free( result_copy );
					result_copy = NULL;
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Freed \"result_copy\" in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}
				else
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "\"result_copy\" was NULL and not freed for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}


				if( found_something_good > 0 )
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Found verified match in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
					if( have_md5 == 0 )
					{
						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Initializing MD5 check in first regex loop\n" );
								fclose( log );
							}
						}
						MD5Init( &md5c );

						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Updating MD5 check in first regex loop\n" );
								fclose( log );
							}
						}
						MD5Update( &md5c, subject, subject_length );

						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Finalizing MD5 check in first regex loop\n" );
								fclose( log );
							}
						}

						MD5Final( md5sig, &md5c );
						have_md5 = 1;
					}

					results = fopen( RESULTS, "a+" );
					if( results != NULL )
					{
						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Writing results to results.txt in first regex loop\n" );
								fclose( log );
							}
						}

						fprintf( results, "%s\t%s\t%s\t%I64u\t", whitelistfile_backslashes, curr_regex->regex_name, result, (file_offset + (chunk_counter * max_memory)) );
						for( md5count = 0; md5count < sizeof( md5sig ); md5count++ )
						{
							fprintf( results, "%02x", md5sig[md5count] );
						}
						if( compressedfile_backslashes != NULL )
						{
							fprintf( results, "\t%s", compressedfile_backslashes );
						}
						fprintf( results, "\n" );
						fclose( results );

						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Done writing results to results.txt in first regex loop\n" );
								fclose( log );
							}
						}
					}
				}
				else
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Did not find verified match in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}


				if( result != NULL )
				{
					free( result );
					result = NULL;
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Freed \"result\" in first regex loop for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}
				else
				{
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "\"result\" was NULL and not freed for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}


				if( debug > 2 )
				{
					log = fopen( LOGFILE, "a+" );
					if( log != NULL )
					{
						fprintf( log, "Done with first regex loop for %s\n", curr_regex->regex_name );
						fclose( log );
					}
				}

				// look for second and subsequent matches
				for(;;)
				{
					int options = 0;
					int start_offset = ovector[0] + 1;
					if( ovector[0] == ovector[1] )
					{
						if( ovector[0] == subject_length )
						{
							break;
						}
						options = PCRE_NOTEMPTY | PCRE_ANCHORED;
					}

					rc = pcre_exec( re, NULL, subject, subject_length, start_offset, options, ovector, OVECCOUNT );
					if( rc == PCRE_ERROR_NOMATCH )
					{
						if( options == 0 )
						{
							break;
						}
						ovector[1] = start_offset + 1;
						continue;
					}

					if( rc < 0 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Matching error %d\n", rc );
							fclose( log );
						}
						if( re != NULL )
						{
							free(re);
							re = NULL;
						}
					}
					else
					{
						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Found potential match in second regex loop for regex %s\n", curr_regex->regex_name );
								fclose( log );
							}
						}
						if( rc == 0 )
						{
							rc = OVECCOUNT / 3;
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "ovector only has room for %d captured substrings\n", rc - 1 );
								fclose( log );
							}
						}

						file_offset = ovector[0];
						char *substring_start = subject + ovector[0];
						int substring_length = ovector[1] - ovector[0];
						result = calloc( substring_length + 1, sizeof( char ));
						if( result == NULL )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "First calloc() failed in second regex loop. Breaking out of for() loop for regex %s\n", curr_regex->regex_name );
								fclose( log );
							}
							if( re != NULL )
							{
								free( re );
								re = NULL;
							}
							break;
						}
						else
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "First calloc() succeeded in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}

						result_copy = calloc( substring_length + 1, sizeof( char ));
						if( result == NULL )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Second calloc failed in second regex loop. Breaking out of for() loop for regex %s\n", curr_regex->regex_name );
								fclose( log );
							}
							if( result != NULL )
							{
								free( result );
								result = NULL;
							}
							if( re != NULL )
							{
								free( re );
								re = NULL;
							}
							break;
						}
						else
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Second calloc() succeeded in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}

						// using memcpy instead of strncpy because of embedded NULLs
						memcpy( result, substring_start, substring_length );
						memcpy( result_copy, substring_start, substring_length );
						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "memcpy() succeeded in second regex loop for %s\n", curr_regex->regex_name );
								fclose( log );
							}
						}

						for( i = 0; i < (ovector[1] - ovector[0]); i++ )
						{
							if( result[i] == '\x0a' || result[i] == '\x00' || result[i] == '\x0d' )
							{
								result[i] = '\x3f';
								result_copy[i] = '\x3f';
							}
						}

						result[substring_length] = '\x00';
						result_copy[substring_length] = '\x00';

						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "characters replaced and NULL-terminated in second regex loop for %s\n", curr_regex->regex_name );
								fclose( log );
							}
						}

						found_possible_cc = 0;
						found_something_good = 0;
						curr_cc = head_cc;
						while( curr_cc )
						{
							if( !strcmp( curr_cc->cc_name, curr_regex->regex_name ))
							{
								found_possible_cc = 1;
							}
							curr_cc = curr_cc->next;
						}

						if( found_possible_cc == 1 )
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Trying mod10 check in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}

							found_something_good = mod10( result_copy );

							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Done with mod10 check in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}
						else
						{
							found_something_good = 1;
						}

						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Attempting to free \"result_copy\" in second regex loop for %s\n", curr_regex->regex_name );
								fclose( log );
							}
						}

						if( result_copy != NULL )
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "\"result_copy\" is not NULL in second regex loop for %s, it is: %s\n", curr_regex->regex_name, result_copy );
									fclose( log );
								}
							}
							free( result_copy );
							result_copy = NULL;
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Freed \"result_copy\" in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}
						else
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "\"result_copy\" was NULL and not freed in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}

						if( found_something_good > 0 )
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Found verified match in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
							if( have_md5 == 0 )
							{
								if( debug > 2 )
								{
									log = fopen( LOGFILE, "a+" );
									if( log != NULL )
									{
										fprintf( log, "Initializing MD5 check in second regex loop\n" );
										fclose( log );
									}
								}
								MD5Init( &md5c );

								if( debug > 2 )
								{
									log = fopen( LOGFILE, "a+" );
									if( log != NULL )
									{
										fprintf( log, "Updating MD5 check in second regex loop\n" );
										fclose( log );
									}
								}
								MD5Update( &md5c, subject, subject_length );

								if( debug > 2 )
								{
									log = fopen( LOGFILE, "a+" );
									if( log != NULL )
									{
										fprintf( log, "Finalizing MD5 check in second regex loop\n" );
										fclose( log );
									}
								}
								MD5Final( md5sig, &md5c );
								have_md5 = 1;
							}

							results = fopen( RESULTS, "a+" );
							if( results != NULL )
							{
								if( debug > 2 )
								{
									log = fopen( LOGFILE, "a+" );
									if( log != NULL )
									{
										fprintf( log, "Writing results to results.txt in second regex loop\n" );
										fclose( log );
									}
								}
								fprintf( results, "%s\t%s\t%s\t%I64u\t", whitelistfile_backslashes, curr_regex->regex_name, result, (file_offset + (chunk_counter * max_memory)) );
								for( md5count = 0; md5count < sizeof( md5sig ); md5count++ )
								{
									fprintf( results, "%02x", md5sig[md5count] );
								}
								if( compressedfile_backslashes != NULL )
								{
									fprintf( results, "\t%s", compressedfile_backslashes );
								}
								fprintf( results, "\n" );
								fclose( results );

								if( debug > 2 )
								{
									log = fopen( LOGFILE, "a+" );
									if( log != NULL )
									{
										fprintf( log, "Done writing results to results.txt in second regex loop\n" );
										fclose( log );
									}
								}
							}
						}
						if( result != NULL )
						{
							free( result );
							result = NULL;
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "Freed \"result\" in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}
						else
						{
							if( debug > 2 )
							{
								log = fopen( LOGFILE, "a+" );
								if( log != NULL )
								{
									fprintf( log, "\"result\" was NULL and not freed in second regex loop for %s\n", curr_regex->regex_name );
									fclose( log );
								}
							}
						}

						if( debug > 2 )
						{
							log = fopen( LOGFILE, "a+" );
							if( log != NULL )
							{
								fprintf( log, "Done with second regex loop for %s\n", curr_regex->regex_name );
								fclose( log );
							}
						}
					}
				}
				if( re != NULL )
				{
					free(re);
					re = NULL;
					if( debug > 2 )
					{
						log = fopen( LOGFILE, "a+" );
						if( log != NULL )
						{
							fprintf( log, "Freed \"re\" for %s\n", curr_regex->regex_name );
							fclose( log );
						}
					}
				}
			}
		}
		curr_regex = curr_regex->next;
	}
}
