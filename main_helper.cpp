#include <curl/curl.h>
#include <iostream>


CURL *curl = NULL;
struct curl_slist *lists = NULL;

std::string ec_login_token;

const char* get_serverUrl();
const char* get_pfxFilePath();
const char* get_pfxFilePasswd();
std::string getLoginToken();


static size_t WriteCallback(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
      return size * nmemb;
}



void curlCleanup()
{
	curl_easy_cleanup(curl);
    curl_global_cleanup();
}


void initialize_curl(void) 
{
    printf("---Initializing curl---");

	std::string url = get_serverUrl();
    url = url + "/api/signing/pkcs11-api/";

    std::string pfx_file_path = get_pfxFilePath();
    std::string pfx_passwd    = get_pfxFilePasswd();

    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();

    if(curl) {
       // Set the target URL
	   curl_easy_setopt(curl, CURLOPT_URL, url.c_str());

       // Set up the PFX file and password
       curl_easy_setopt(curl, CURLOPT_SSLCERT, pfx_file_path.c_str());
       curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "P12");
       curl_easy_setopt(curl, CURLOPT_KEYPASSWD, pfx_passwd.c_str());


       // Set the request type to POST
       curl_easy_setopt(curl, CURLOPT_POST, 1L);

       lists = curl_slist_append(lists, "Content-Type: application/json" );

       std::string authorizationHeader = std::string("Authorization: Bearer ")+ ec_login_token;

	   lists = curl_slist_append(lists, authorizationHeader.c_str());

       std::string referer_header = std::string("Referer: PKCS11_CLIENT");
	   lists = curl_slist_append(lists, referer_header.c_str());

       std::string csrf_header = std::string("X-CSRFToken: ") + ec_login_token;
       lists = curl_slist_append(lists, csrf_header.c_str());

       // Set the HTTP header
       curl_easy_setopt(curl, CURLOPT_HTTPHEADER, lists);

       // Set the callback function to handle response data
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

       //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	   // Call at exit
	   atexit(curlCleanup);
 
	}
}


void performPostRequest( std::string &readBuffer, const char* postData)
{

    readBuffer.clear();
	// Set the POST data
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postData);	

    // Set pointer to hold the response data
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)&readBuffer);

	// Perform the request
	CURLcode res = curl_easy_perform(curl);

	// Check for errors
	if (res != CURLE_OK)
		fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

}


void setLoginToken(){
    ec_login_token = getLoginToken();
}
