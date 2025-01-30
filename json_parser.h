#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include "pkcs11.h"
#include "data_mapping.h"

template <typename T>
class JsonParser {
public:
    JsonParser(const char* jsonBuffer, std::string name) : jsonBuffer_(jsonBuffer),apiName_(name) {}

    bool parse();
    unsigned int processJson(T ** parsedData); 

private:
	unsigned int populateData(CK_SLOT_INFO*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_TOKEN_INFO*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_SESSION_HANDLE*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_MECHANISM_INFO*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_SESSION_INFO*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_ATTRIBUTE*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_BYTE*** data,const rapidjson::Value& additionalInfo);
	unsigned int populateData(CK_INFO*** data,const rapidjson::Value& additionalInfo);
	
	const char* jsonBuffer_;
    rapidjson::Document document_;
    std::string apiName_;
};


class MechanismList {
public:
    static MechanismList& getInstance() {
        static MechanismList instance; // Static local variable ensures initialization only once
        return instance;
    }

    void setArray(const rapidjson::Value &m_list, size_t len) {
        arr = new unsigned long[len];
        unsigned int newlen = 0;  
        for (size_t i = 0; i < len; ++i) {
            std::string mechanism = m_list[i].GetString();
			if (mechanismMap.find(mechanism) != mechanismMap.end()) {
                arr[i] = mechanismMap[mechanism];
                newlen++;
			} else {
				std::cout << "Mechanism: " << mechanism << " not found in mapping." << std::endl;
			    //throw std::exception();  	
			}
        }
        length = newlen;
    }

    unsigned long* getArray() const {
        return arr;
    }

    size_t getLength() const {
        return length;
    }

private:
    MechanismList() { arr = NULL; length = 0 ;} // Private constructor to prevent instantiation
    ~MechanismList() {} // Private destructor to prevent deletion
    MechanismList(const MechanismList&) = delete; // Delete copy constructor
    MechanismList& operator=(const MechanismList&) = delete; // Delete assignment operator

    unsigned long* arr;
    size_t length;
};

// Include the template implementation in the header file
#include "json_parser.tpp"

#endif // JSON_PARSER_H
