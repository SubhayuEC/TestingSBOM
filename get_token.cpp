#include <iostream>
#include <string>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <array>
#include <rapidjson/document.h>

#ifdef _WIN32
#define pclose _pclose
#define popen _popen
#endif

using namespace rapidjson;

const char* get_serverUrl();

// Function to execute the curl command and get the response
std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

std::string getLoginToken() {
    // Construct the curl command
    std::string serverUrl = get_serverUrl();
    serverUrl = serverUrl + "/api/auth/GetLoginToken/"; 

#ifdef _WIN32
    std::string command = "curl  -s -X POST "
                          "-H \"Content-Type:application/json\" "
                          "-H \"Referer: EC_PKCS11_CLIENT\" "
                          "-H \"User-Agent: PKCS11_client\" "
                          "-H \"Accept: */*\" "
                          "-d \"{\\\"code\\\": \\\"8^@^!^$U3QXS5Xtu2vf\\\",\\\"user\\\": \\\"Sam@encryptionconsulting.com\\\",\\\"identityType\\\": 1}\" "
                          "\"" + serverUrl + "\"";
#else
	std::string command = "curl -s -X POST "
                          "-H \"Content-Type:application/json\" "
                          "-H \"Referer: EC_PKCS11_CLIENT\" "
                          "-H \"User-Agent: PKCS11_client\" "
                          "-H \"Accept: */*\" "
                          "-d '{"
                          "\"code\": \"8@!$U3QXS5Xtu2vf\","
                          "\"user\": \"Sam@encryptionconsulting.com\","
                          "\"identityType\": 1"
                          "}' "
                          "'" + serverUrl + "'";
#endif

    // Execute the curl command and get the response
    //printf("   command   :%s\n",command.c_str());
    std::string response = exec(command.c_str());
    //printf("   response   :%s\n",response.c_str());

    // Find the start of the JSON body (after headers)
    size_t json_start = response.find("{");
    if (json_start != std::string::npos) {
        response = response.substr(json_start);
    }

    // Parse the JSON response using RapidJSON
    Document document;
    if (document.Parse(response.c_str()).HasParseError()) {
        printf( "Error parsing JSON response\n") ;
        exit(1);
    }

    // Extract the token value
    if (document.HasMember("token") && document["token"].IsString()) {
        std::string token = document["token"].GetString();
        // Print the token value
        //std::cout << "Token: " << token << std::endl;
		return token;
    } else {
        std::cerr << "Token not found in JSON response" << std::endl;
    }

    return "";
}
