// StrFile.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <fstream>
#include <istream>
#include <iostream>
#include <string>
#include <sstream>
#include "base64.cpp"

using namespace std;


int main(int argc, char** argv) {

  if (argc == 2) {
    std::string encodedStr = argv[1];
    std::string decodedStr = base64_decode(encodedStr);    
    cout << decodedStr;
  } else if (argc == 3) {
    std::string encodedStr = argv[1];
    std::string decodedStr = base64_decode(encodedStr);    
    char* filename = argv[2];
    fstream myfile;
    myfile.open (filename, ios::out | ios::trunc);
    myfile.write(decodedStr.data(), decodedStr.length());
  	return 0;
  } else {
    cout << "StrFile decodes a Base-64 encoded string and writes it to a file (or to stdout).\n";
    cout << "The first parameter is the B64-encoded string. It cannot contain any line breaks.\n";
    cout << "The second parameter is optional, and may indicate a filename in which to store \n";
    cout << "the decoded text. If no filename is specified, the text will be sent to stdout.\n";
    cout << "=================================================================================\n";
    cout << "Usage 1:  StrFile aGVsbG8gd29ybGQ=                (prints to console)\n";
    cout << "Usage 2:  StrFile aGVsbG8gd29ybGQ= > outfile.txt  (redirects to file)\n";
    cout << "Usage 3:  StrFile aGVsbG8gd29ybGQ= outfile.txt    (writes to file)\n\n";
  }


}

