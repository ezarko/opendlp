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

#define SLEEP_TIME 500000
#define MAX_LINE 8096

#define LOGFILE "log.txt"
#define STATUS "status.txt"
#define CONFIG "config.ini"
#define COUNTER "counter.txt"
#define ALLDIR "all_dir.txt"
#define WHITELIST_DIR "whitelist_dir.txt"
#define WHITELIST_FILE "whitelist_file.txt"
#define RESULTS "results.txt"
#define BYTES "bytes.txt"

SERVICE_STATUS ServiceStatus;
SERVICE_STATUS_HANDLE hStatus;

int upload_stuff( int );
void ServiceMain(int argc, char** argv); 
void ControlHandler(DWORD request); 
int InitService();
int WriteToLog(char*);
int read_config();
// int dynamic_fgets(char**, int*, FILE*);
void choppy( char* );
void replace_char( char*, char, char );
int mod10( char* );
void do_regex( char*, unsigned long long, char*, char*, unsigned long long );
void init_scan( void );
void recurse_dir_list( void );
void whitelist( void );
void search( void );
int unzip( char[] );
int fixpath( const char*, char* );
int showdir( const char* );
int deletedir( const char* );

/* Globals */
char homedir[MAX_LINE];
char ext_opt[16];
char dir_opt[16];
int time_wait;
FILE *counter;
unsigned long long file_number;
unsigned long long bytes_processed;
unsigned long long total_file_size;
unsigned long long total_files;
int status;
struct list_ext
{
	char ext[MAX_LINE];
	struct list_ext *next;
};
typedef struct list_ext exts;
exts *curr_ext;
exts *head_ext;

struct list_zip
{
	char zip[MAX_LINE];
	struct list_zip *next;
};
typedef struct list_zip zips;
zips *curr_zip;
zips *head_zip;

struct directories
{
	char dir[MAX_LINE];
	struct directories *next;
};
typedef struct directories dirs;
dirs *curr_dir;
dirs *head_dir;

struct regexes
{
	char regex_name[128];
	char regex_value[2048];
	struct regexes *next;
};
typedef struct regexes regex;
regex *curr_regex;
regex *head_regex;

struct credit_cards
{
	char cc_name[128];
	struct credit_cards *next;
};
typedef struct credit_cards cc;
cc *curr_cc;
cc *head_cc;

char url[256];
char urluser[33];
char urlpass[33];
int debug;
char tracker[33];
char scan[65];
char profile[65];
unsigned long long max_memory;
WIN32_FIND_DATA *fd;
