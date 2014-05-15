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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>
#include <curl/types.h>
#include <curl/easy.h>
#include "globals.h"

int upload_stuff( int status )
{
	FILE* log;
	CURL *curl;
	CURLcode res;
	const char *pPassphrase = NULL;
	static const char *pCertFile = "client.pem";
	static const char *pCACertFile="server.pem";
	const char *pKeyName;
	const char *pKeyType;
	const char *pEngine;
	int ret;

	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;
	struct curl_slist *headerlist=NULL;
	static const char buf[] = "Expect:";
	struct stat filebuf;

	int max_name_length = 512;
	char hostname[max_name_length];
	char domainname[max_name_length];

	log = fopen( LOGFILE, "a+" );
	if( log != NULL )
	{
		fprintf( log, "Trying to upload with status = %i\n", status );
		fclose( log );
	}

	if( GetComputerNameA( hostname, &max_name_length ) == 0 )
	{
		WriteToLog( "*** ERROR: GetComputerNameA() failed ***\n" );
		return -1;
	}

	// get domain name?

	pKeyName  = "client.pem";
	pKeyType  = "PEM";
	pEngine   = NULL;

	// ?hostname=whatever
	if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "hostname", CURLFORM_COPYCONTENTS, hostname, CURLFORM_END )) != 0 )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
			fclose( log );
		}
//		curl_global_cleanup();	
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_formadd hostname\n" );
	}

	// &tracker=whatever
	if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "tracker", CURLFORM_COPYCONTENTS, tracker, CURLFORM_END )) != 0 )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
			fclose( log );
		}
//		curl_global_cleanup();	
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_formadd tracker\n" );
	}

	// &scan=whatever
	if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "scan", CURLFORM_COPYCONTENTS, scan, CURLFORM_END )) != 0 )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
			fclose( log );
		}
//		curl_global_cleanup();	
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_formadd scan\n" );
	}
	// &profile=whatever
	if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "profile", CURLFORM_COPYCONTENTS, profile, CURLFORM_END )) != 0 )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
			fclose( log );
		}
//		curl_global_cleanup();	
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_formadd profile\n" );
	}

	// &status=X
	char statusbuf[2];
	sprintf( statusbuf, "%i", status );
	if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "status", CURLFORM_COPYCONTENTS, statusbuf, CURLFORM_END )) != 0 )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_formadd(status) failed. Error code = %i ***\n", ret );
			fclose( log );
		}
		curl_formfree( formpost );
//		curl_global_cleanup();
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_formadd status\n" );
	}

	// &log=log.txt
	if( !stat( LOGFILE, &filebuf ))
	{
		if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "log", CURLFORM_FILE, LOGFILE, CURLFORM_END )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
				fclose( log );
			}
			curl_formfree( formpost );
//			curl_global_cleanup();
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "curl_formadd log\n" );
		}
	}

	if( status == 1 )
	{
		// upload total files and total bytes to be scanned
		char sizebuf[256];
		sprintf( sizebuf, "%I64u", total_file_size );
		if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "bytestotal", CURLFORM_COPYCONTENTS, sizebuf, CURLFORM_END )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_formadd(bytestotal) failed. Error code = %i ***\n", ret );
				fclose( log );
			}
			curl_formfree( formpost );
//			curl_global_cleanup();
			return -1;
		}

		if( debug > 1 )
		{
			WriteToLog( "curl_formadd bytestotal\n" );
		}

		char filebuf_files[256];
		sprintf( filebuf_files, "%I64u", total_files );
		if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "filestotal", CURLFORM_COPYCONTENTS, filebuf_files, CURLFORM_END )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_formadd(filestotal) failed. Error code = %i ***\n", ret );
				fclose( log );
			}
			curl_formfree( formpost );
//			curl_global_cleanup();
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "curl_formadd filestotal\n" );
		}
	}

	if( status > 1 )
	{
		// uploading actual results here
		// &results=results.txt
		if( !stat( RESULTS, &filebuf ))
		{
			if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "results", CURLFORM_FILE, RESULTS, CURLFORM_END )) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
					fclose( log );
				}
				curl_formfree( formpost );
//				curl_global_cleanup();
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "curl_formadd results\n" );
			}
		}

		// &filesscanned=12345
		char filebuf_files[256];
		sprintf( filebuf_files, "%I64u", file_number );

		if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "filesscanned", CURLFORM_COPYCONTENTS, filebuf_files, CURLFORM_END )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
				fclose( log );
			}
			curl_formfree( formpost );
//			curl_global_cleanup();
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "curl_formadd filesscanned\n" );
		}

		// &bytesscanned=12345
		char bytebuf[256];
		sprintf( bytebuf, "%I64u", bytes_processed );

		if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "bytesscanned", CURLFORM_COPYCONTENTS, bytebuf, CURLFORM_END )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
				fclose( log );
			}
			curl_formfree( formpost );
//			curl_global_cleanup();
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "curl_formadd bytesscanned\n" );
		}


		// send message to uninstall with last batch of results/logs
		if( status == 3 )
		{
			// &uninstall=1
			if(( ret = curl_formadd( &formpost, &lastptr, CURLFORM_COPYNAME, "uninstall", CURLFORM_COPYCONTENTS, "1", CURLFORM_END )) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_formadd() failed. Error code = %i ***\n", ret );
					fclose( log );
				}
				curl_formfree( formpost );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "curl_formadd uninstall\n" );
			}
		}
	}
	// end status = 2 or status = 3

	if(( curl = curl_easy_init() ) == NULL )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_easy_init() failed ***\n" );
			fclose( log );
		}
		curl_formfree( formpost );
//		curl_global_cleanup();	
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_easy_init\n" );
	}

	if(( headerlist = curl_slist_append(headerlist, buf)) == NULL )
	{
		log = fopen( LOGFILE, "a+" );
		if( log != NULL )
		{
			fprintf( log, "*** ERROR: curl_slist_append() failed ***\n" );
			fclose( log );
		}
		curl_easy_cleanup( curl );
		curl_formfree( formpost );
//		curl_global_cleanup();
		return -1;
	}
	if( debug > 1 )
	{
		WriteToLog( "curl_slist_append\n" );
	}

	if( curl )
	{
		if(( ret = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerlist)) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_HTTPHEADER ***\n" );
				fclose( log );
			}
			curl_easy_cleanup( curl );
			curl_formfree( formpost );
			curl_slist_free_all( headerlist );
//			curl_global_cleanup();	
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "CURLOPT_HTTPHEADER\n" );
		}

		if(( ret = curl_easy_setopt( curl, CURLOPT_USERNAME, urluser )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_USERNAME ***\n" );
				fclose( log );
			}
			curl_easy_cleanup( curl );
			curl_formfree( formpost );
			curl_slist_free_all( headerlist );
//			curl_global_cleanup();	
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "CURLOPT_USERNAME\n" );
		}

		if(( ret = curl_easy_setopt( curl, CURLOPT_PASSWORD, urlpass )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_PASSWORD ***\n" );
				fclose( log );
			}
			curl_easy_cleanup( curl );
			curl_formfree( formpost );
			curl_slist_free_all( headerlist );
//			curl_global_cleanup();	
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "CURLOPT_PASSWORD\n" );
		}

		if(( ret = curl_easy_setopt( curl, CURLOPT_URL, url )) != 0 )
		{
			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_URL ***\n" );
				fclose( log );
			}
			curl_easy_cleanup( curl );
			curl_formfree( formpost );
			curl_slist_free_all( headerlist );
//			curl_global_cleanup();	
			return -1;
		}
		if( debug > 1 )
		{
			WriteToLog( "CURLOPT_URL\n" );
		}

		while( 1 )
		{
			if(( ret = curl_easy_setopt(curl,CURLOPT_SSLCERTTYPE,"PEM")) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_SSLCERTTYPE ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_SSLCERTTYPE\n" );
			}

			if(( ret = curl_easy_setopt(curl,CURLOPT_SSLCERT,pCertFile)) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_SSLCERT ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_SSLCERT\n" );
			}

			if(( ret = curl_easy_setopt(curl,CURLOPT_SSLKEYTYPE,pKeyType)) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_SSLKEYTYPE ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_SSLKEYTYPE\n" );
			}

			if(( ret = curl_easy_setopt(curl,CURLOPT_SSLKEY,pKeyName)) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_SSLKEY ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_SSLKEY\n" );
			}

			if(( ret = curl_easy_setopt(curl,CURLOPT_CAINFO,pCACertFile)) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_CAINFO ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_CAINFO\n" );
			}

			if(( ret = curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,1)) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_SSL_VERIFYPEER ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_SSL_VERIFYPEER\n" );
			}

			if(( ret = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST,0)) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_SSL_VERIFYHOST ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_SSL_VERIFYHOST\n" );
			}

			if(( ret = curl_easy_setopt( curl, CURLOPT_HTTPPOST, formpost )) != 0 )
			{
				log = fopen( LOGFILE, "a+" );
				if( log != NULL )
				{
					fprintf( log, "*** ERROR: curl_easy_setopt() failed on setting CURLOPT_HTTPPOST ***\n" );
					fclose( log );
				}
				curl_easy_cleanup( curl );
				curl_formfree( formpost );
				curl_slist_free_all( headerlist );
//				curl_global_cleanup();	
				return -1;
			}
			if( debug > 1 )
			{
				WriteToLog( "CURLOPT_HTTPPOST\n" );
			}

			res = curl_easy_perform( curl );

			log = fopen( LOGFILE, "a+" );
			if( log != NULL )
			{
				fprintf( log, "Upload attempted. libcurl returned: %i\n", res );
				fclose( log );
			}

			break;
		}

		if( debug > 1 )
		{
			WriteToLog( "Trying curl_easy_cleanup()\n" );
		}
		curl_easy_cleanup( curl );
		if( debug > 1 )
		{
			 WriteToLog( "curl_easy_cleanup\n" );
		}
		curl_formfree( formpost );
		if( debug > 1 )
		{
			WriteToLog( "curl_formfree\n" );
		}
		curl_slist_free_all( headerlist );
		if( debug > 1 )
		{
			WriteToLog( "curl_slist_free_all\n" );
		}
	}
	return res;
}


