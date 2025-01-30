#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "ini.h"

#ifdef _WIN32
#define strdup _strdup
#endif

typedef struct
{
    const char* name;
    const char* url;
    const char* path;
    const char* passwd;
} configuration;

// Global configuration object
static configuration config;

static int handler(void* user, const char* section, const char* name,
                   const char* value)
{
    configuration* pconfig = (configuration*)user;

    #define MATCH(s, n) strcmp(section, s) == 0 && strcmp(name, n) == 0

    if (MATCH("logconfig_file", "name")) {
        pconfig->name =  strdup(value);
    } else if (MATCH("server_url", "url")) {
        pconfig->url = strdup(value);
    } else if (MATCH("pfxfile_path", "path")) {
        pconfig->path = strdup(value);
    } else if (MATCH("pfxfile_passwd", "passwd")) {
        pconfig->passwd = strdup(value);
    } else {
        return 0;  /* unknown section/name, error */
    }
    return 1;
}


// Function to get the logger configuration file name
const char* get_loggerConfigFileName() {
    return config.name;
}


// Function to get the server URL
const char* get_serverUrl() {
    return config.url;
}


// Function to get the pfx file path 
const char* get_pfxFilePath() {
    return config.path;
}


// Function to get the server URL
const char* get_pfxFilePasswd() {
    return config.passwd;
}


void init_ini_file(){

	memset(&config, 0, sizeof(config));

    if (ini_parse("ec_pkcs11client.ini", handler, &config) < 0) {
        printf("Can't load 'ec_pkcs11client.ini'\n");
        exit(1);
    }
}
