#include"pkcs11.h"
#include <iostream>
#include <stdexcept>
#include <unordered_map>
#include <cstring>
#include <vector>

#include "rapidjson/document.h"


template <typename T>
bool JsonParser<T>::parse() {
    document_.Parse(jsonBuffer_);
    return !document_.HasParseError() && document_.IsObject();
}


template <typename T>
unsigned int  JsonParser<T>::processJson(T** parsedData) {
    int result;

    if (!parse()) {
        std::cerr << "Failed to parse JSON." << std::endl;
        throw std::exception();
    }

    // Access and process different fields based on your JSON structure
    if (document_.HasMember("result") && document_["result"].IsInt()) {
        result = document_["result"].GetInt();
    }

    if (result != 0){ 
        std::cout<<"----- pkcs11 API encountered error-----"<<std::endl;
        throw std::exception();
    }

    if (document_.HasMember("additional_info") && document_["additional_info"].IsObject()) {
        const rapidjson::Value& additionalInfo = document_["additional_info"];

        return populateData(&parsedData, additionalInfo);
    }
    else{
        std::cout<<"---Invalid json payload ------"<<std::endl;
        throw std::exception();
    }

}

template <typename T>
unsigned int JsonParser<T>::populateData(CK_SLOT_INFO*** data,const rapidjson::Value& additionalInfo){

	std::unordered_map<std::string, int> myDict;

    // Add key-value pairs to the dictionary
    myDict["CKF_TOKEN_PRESENT"] = CKF_TOKEN_PRESENT;
    myDict["CKF_REMOVABLE_DEVICE"] = CKF_REMOVABLE_DEVICE;
    myDict["CKF_HW_SLOT"] = CKF_HW_SLOT; 
    myDict["CKF_ARRAY_ATTRIBUTE"] = CKF_ARRAY_ATTRIBUTE; 

	if (additionalInfo.HasMember("slotInfo") && additionalInfo["slotInfo"].IsObject()) {
		const rapidjson::Value& slotInfo = additionalInfo["slotInfo"];

		if (slotInfo.HasMember("slotDescription") && slotInfo["slotDescription"].IsString()) {
			strncpy((char*)((**data)->slotDescription), slotInfo["slotDescription"].GetString(), sizeof((**data)->slotDescription));
		}

		//manufacturerID
		if (slotInfo.HasMember("manufacturerID") && slotInfo["manufacturerID"].IsString()) {
			strncpy((char*)(**data)->manufacturerID, slotInfo["manufacturerID"].GetString(),sizeof((**data)->manufacturerID));
		}

		// Access the "flags" field
		if (slotInfo.HasMember("flags") && slotInfo["flags"].IsArray()) {
			const rapidjson::Value& flags = slotInfo["flags"];

			int result = 0;
			if (flags[0].IsString()) {
				result = myDict[flags[0].GetString()];		
			}
 
			for (rapidjson::SizeType i = 1; i < flags.Size(); ++i) {
				if (flags[i].IsString()) {
					result = result | myDict[flags[i].GetString()];
				}
			}
			(**data)->flags = result;
		}

        // hardwareVersion
		if (slotInfo.HasMember("hardwareVersion") && slotInfo["hardwareVersion"].IsString()){
			std::string hardwareVersion = slotInfo["hardwareVersion"].GetString();

			// Find the position of the decimal point
			size_t dotPosition = hardwareVersion.find('.');

			if (dotPosition != std::string::npos) {
				// Extract the major and minor parts as strings
				std::string majorPart = hardwareVersion.substr(0, dotPosition);
				std::string minorPart = hardwareVersion.substr(dotPosition + 1);

				(**data)->hardwareVersion.major = static_cast<unsigned char>(std::stoi(majorPart));
				(**data)->hardwareVersion.minor = static_cast<unsigned char>(std::stoi(minorPart));

			} else {
				// Handle the case when there is no decimal point
				(**data)->hardwareVersion.major = static_cast<unsigned char>(std::stoi(hardwareVersion));
				(**data)->hardwareVersion.minor = static_cast<unsigned char>(0);
			}
		}

		//firmware_version
	    if (slotInfo.HasMember("firmwareVersion") && slotInfo["firmwareVersion"].IsString()){
            std::string firmwareVersion = slotInfo["firmwareVersion"].GetString();

            // Find the position of the decimal point
            size_t dotPosition = firmwareVersion.find('.');

            if (dotPosition != std::string::npos) {
                // Extract the major and minor parts as strings
                std::string majorPart = firmwareVersion.substr(0, dotPosition);
                std::string minorPart = firmwareVersion.substr(dotPosition + 1);

                (**data)->firmwareVersion.major = static_cast<unsigned char>(std::stoi(majorPart));
                (**data)->firmwareVersion.minor = static_cast<unsigned char>(std::stoi(minorPart));

            } else {
                // Handle the case when there is no decimal point
                (**data)->firmwareVersion.major = static_cast<unsigned char>(std::stoi(firmwareVersion));
                (**data)->firmwareVersion.minor = static_cast<unsigned char>(0);
            }
        }// Firmware_version end
	}	
    return 0;
}


template <typename T>
unsigned int  JsonParser<T>::populateData(CK_TOKEN_INFO*** data,const rapidjson::Value& additionalInfo){
    std::unordered_map<std::string, int> tokenInfoFlagsDict;

    tokenInfoFlagsDict["CKF_RNG"] = CKF_RNG;
    tokenInfoFlagsDict["CKF_WRITE_PROTECTED"] = CKF_WRITE_PROTECTED;
    tokenInfoFlagsDict["CKF_LOGIN_REQUIRED"] = CKF_LOGIN_REQUIRED;
    tokenInfoFlagsDict["CKF_USER_PIN_INITIALIZED"] = CKF_USER_PIN_INITIALIZED;
    tokenInfoFlagsDict["CKF_RESTORE_KEY_NOT_NEEDED"] = CKF_RESTORE_KEY_NOT_NEEDED;
    tokenInfoFlagsDict["CKF_CLOCK_ON_TOKEN"] = CKF_CLOCK_ON_TOKEN;
    tokenInfoFlagsDict["CKF_PROTECTED_AUTHENTICATION_PATH"] = CKF_PROTECTED_AUTHENTICATION_PATH;
    tokenInfoFlagsDict["CKF_DUAL_CRYPTO_OPERATIONS"] = CKF_DUAL_CRYPTO_OPERATIONS;
    tokenInfoFlagsDict["CKF_TOKEN_INITIALIZED"] = CKF_TOKEN_INITIALIZED;
    tokenInfoFlagsDict["CKF_SECONDARY_AUTHENTICATION"] = CKF_SECONDARY_AUTHENTICATION;
    tokenInfoFlagsDict["CKF_USER_PIN_COUNT_LOW"] = CKF_USER_PIN_COUNT_LOW;
    tokenInfoFlagsDict["CKF_USER_PIN_FINAL_TRY"] = CKF_USER_PIN_FINAL_TRY;
    tokenInfoFlagsDict["CKF_USER_PIN_LOCKED"] = CKF_USER_PIN_LOCKED;
    tokenInfoFlagsDict["CKF_USER_PIN_TO_BE_CHANGED"] = CKF_USER_PIN_TO_BE_CHANGED;
    tokenInfoFlagsDict["CKF_SO_PIN_COUNT_LOW"] = CKF_SO_PIN_COUNT_LOW;
    tokenInfoFlagsDict["CKF_SO_PIN_FINAL_TRY"] = CKF_SO_PIN_FINAL_TRY;
    tokenInfoFlagsDict["CKF_SO_PIN_LOCKED"] = CKF_SO_PIN_LOCKED;
    tokenInfoFlagsDict["CKF_SO_PIN_TO_BE_CHANGED"] = CKF_SO_PIN_TO_BE_CHANGED;

	if (additionalInfo.HasMember("tokenInfo") && additionalInfo["tokenInfo"].IsObject()) {
        const rapidjson::Value& tokenInfo = additionalInfo["tokenInfo"];

		//label
        if (tokenInfo.HasMember("label") && tokenInfo["label"].IsString()) {
            strncpy((char*)(**data)->label, tokenInfo["label"].GetString(), sizeof((**data)->label));
        }

		//manufacturerID
        if (tokenInfo.HasMember("manufacturerID") && tokenInfo["manufacturerID"].IsString()) {
            strncpy((char*)(**data)->manufacturerID, tokenInfo["manufacturerID"].GetString(), sizeof((**data)->manufacturerID));
        }

		//model
        if (tokenInfo.HasMember("model") && tokenInfo["model"].IsString()) {
            strncpy((char*)(**data)->model, tokenInfo["model"].GetString(), sizeof((**data)->model));
        }

		//serialNumber
        if (tokenInfo.HasMember("serialNumber") && tokenInfo["serialNumber"].IsString()) {
            strncpy((char*)(**data)->serialNumber, tokenInfo["serialNumber"].GetString(), sizeof((**data)->serialNumber));
        }

		// Access the "flags" field
		if (tokenInfo.HasMember("flags") && tokenInfo["flags"].IsArray()) {
			const rapidjson::Value& flags = tokenInfo["flags"];

			int result = 0;
            if (flags[0].IsString()) {
                result = tokenInfoFlagsDict[flags[0].GetString()];
            }

            for (rapidjson::SizeType i = 1; i < flags.Size(); ++i) {
                if (flags[i].IsString()) {
                    result = result | tokenInfoFlagsDict[flags[i].GetString()];
                }
            }
            (**data)->flags = result;
        }//Flags end

		// Accessing 'ulMaxSessionCount' field
        if (tokenInfo.HasMember("ulMaxSessionCount") && tokenInfo["ulMaxSessionCount"].IsInt()) {
           (**data)->ulMaxSessionCount  = tokenInfo["ulMaxSessionCount"].GetInt();
		}

		// Accessing 'ulSessionCount' field
        if (tokenInfo.HasMember("ulSessionCount") && tokenInfo["ulSessionCount"].IsInt()) {
           (**data)->ulSessionCount  = tokenInfo["ulSessionCount"].GetInt();
		}

		// Accessing 'ulMaxRwSessionCount' field
        if (tokenInfo.HasMember("ulMaxRwSessionCount") && tokenInfo["ulMaxRwSessionCount"].IsInt()) {
           (**data)->ulMaxRwSessionCount  = tokenInfo["ulMaxRwSessionCount"].GetInt();
		}

		// Accessing 'ulRwSessionCount' field
        if (tokenInfo.HasMember("ulRwSessionCount") && tokenInfo["ulRwSessionCount"].IsInt()) {
           (**data)->ulRwSessionCount  = tokenInfo["ulRwSessionCount"].GetInt();
		}

		// Accessing 'ulMaxPinLen' field
        if (tokenInfo.HasMember("ulMaxSessionCount") && tokenInfo["ulMaxSessionCount"].IsInt()) {
           (**data)->ulMaxSessionCount  = tokenInfo["ulMaxSessionCount"].GetInt();
		}

		// Accessing 'ulMinPinLen' field
        if (tokenInfo.HasMember("ulMinPinLen") && tokenInfo["ulMinPinLen"].IsInt()) {
           (**data)->ulMinPinLen  = tokenInfo["ulMinPinLen"].GetInt();
		}

		// Accessing 'ulTotalPublicMemory' field
        if (tokenInfo.HasMember("ulTotalPublicMemory") && tokenInfo["ulTotalPublicMemory"].IsInt()) {
           (**data)->ulTotalPublicMemory  = tokenInfo["ulTotalPublicMemory"].GetInt();
		}

		// Accessing 'ulFreePublicMemory' field
        if (tokenInfo.HasMember("ulFreePublicMemory") && tokenInfo["ulFreePublicMemory"].IsInt()) {
           (**data)->ulFreePublicMemory  = tokenInfo["ulFreePublicMemory"].GetInt();
		}

		// Accessing 'ulTotalPrivateMemory' field
        if (tokenInfo.HasMember("ulTotalPrivateMemory") && tokenInfo["ulTotalPrivateMemory"].IsInt()) {
           (**data)->ulTotalPrivateMemory  = tokenInfo["ulTotalPrivateMemory"].GetInt();
		}

		// Accessing 'ulFreePrivateMemory' field
        if (tokenInfo.HasMember("ulFreePrivateMemory") && tokenInfo["ulFreePrivateMemory"].IsInt()) {
           (**data)->ulFreePrivateMemory  = tokenInfo["ulFreePrivateMemory"].GetInt();
		}

		// Accessing 'hardwareVersion' field
        if (tokenInfo.HasMember("hardwareVersion") && tokenInfo["hardwareVersion"].IsArray()) {
            const rapidjson::Value& hardwareVersion = tokenInfo["hardwareVersion"];

            if (hardwareVersion.Size() == 2 && hardwareVersion[0].IsInt() && hardwareVersion[1].IsInt()) {
                (**data)->hardwareVersion.major = hardwareVersion[0].GetInt();
                (**data)->hardwareVersion.minor = hardwareVersion[1].GetInt();
            }
        }

		// Accessing 'firmwareVersion' field
        if (tokenInfo.HasMember("firmwareVersion") && tokenInfo["firmwareVersion"].IsArray()) {
            const rapidjson::Value& firmwareVersion = tokenInfo["firmwareVersion"];

            if (firmwareVersion.Size() == 2 && firmwareVersion[0].IsInt() && firmwareVersion[1].IsInt()) {
                (**data)->firmwareVersion.major = firmwareVersion[0].GetInt();
                (**data)->firmwareVersion.minor = firmwareVersion[1].GetInt();
            }
        }

		//utcTime
        if (tokenInfo.HasMember("utcTime") && tokenInfo["utcTime"].IsString()) {
            strncpy((char*)(**data)->utcTime, tokenInfo["utcTime"].GetString(), sizeof((**data)->utcTime));
        }

    }
    return 0;
}

template <typename T>
unsigned int JsonParser<T>::populateData(CK_SESSION_HANDLE*** data,const rapidjson::Value& additionalInfo){

    if (strcmp(apiName_.c_str(),"C_OpenSession")== 0)
    {
        std::cout<<"---api name ----"<< apiName_.c_str() <<std::endl;

        if (additionalInfo.HasMember("session_handle") && additionalInfo["session_handle"].IsInt()) {
           unsigned int session_handle   = additionalInfo["session_handle"].GetInt();
           std::cout<<"-----Session Handle------- "<< session_handle <<std::endl;
           ***data = session_handle;
        }
    }

    if (strcmp(apiName_.c_str(),"C_GetSlotList")== 0)
    {
        if (additionalInfo.HasMember("slot_list") && additionalInfo["slot_list"].IsArray()) {
            const rapidjson::Value& s_list = additionalInfo["slot_list"]; 
            unsigned int length = s_list.Size();

            if (**data){
               for(int i=0; i < length; ++i){
                   (**data)[i]  = s_list[i].GetInt();
                }
                return length;
            }else{

                return length;
            }
            
        }
    }

    if (strcmp(apiName_.c_str(),"C_GetMechanismList")== 0)
    {
        if (additionalInfo.HasMember("mechanism_list") && additionalInfo["mechanism_list"].IsArray()) {
            const rapidjson::Value& m_list = additionalInfo["mechanism_list"]; 

            int length = m_list.Size();
            MechanismList& instance = MechanismList::getInstance();
            instance.setArray(m_list, length);

            ***data = instance.getLength();
        }
    }

    if (strcmp(apiName_.c_str(),"C_Login")== 0){}

    if (strcmp(apiName_.c_str(),"C_FindObjectsInit")== 0){}

    if (strcmp(apiName_.c_str(),"C_FindObjects")== 0){
        if (additionalInfo.HasMember("obj_list") && additionalInfo["obj_list"].IsArray()) {
            const rapidjson::Value& obj_list = additionalInfo["obj_list"]; 

            rapidjson::SizeType obj_len = obj_list.Size();
            unsigned int i = 0;
            for ( ;i < obj_len; i++) {
                (**data)[i] = obj_list[i].GetInt(); 
            }
            return i;
        }           

    }

    if (strcmp(apiName_.c_str(),"C_FindObjectsFinal")== 0){}
    if (strcmp(apiName_.c_str(),"C_SignInit")== 0){}
    if (strcmp(apiName_.c_str(),"C_SignUpdate")== 0){}

    return 0;
}


template <typename T>
unsigned int  JsonParser<T>::populateData(CK_MECHANISM_INFO*** data,const rapidjson::Value& additionalInfo){
	if (additionalInfo.HasMember("mechanism_info") && additionalInfo["mechanism_info"].IsObject()) {
        const rapidjson::Value& mechanism_info = additionalInfo["mechanism_info"];

        //ulMinKeySize
        if (mechanism_info.HasMember("ulMinKeySize") && mechanism_info["ulMinKeySize"].IsInt()) {
           (**data)->ulMinKeySize  = mechanism_info["ulMinKeySize"].GetInt();
        }

        //ulMaxKeySize
        if (mechanism_info.HasMember("ulMaxKeySize") && mechanism_info["ulMaxKeySize"].IsInt()) {
           (**data)->ulMaxKeySize  = mechanism_info["ulMaxKeySize"].GetInt();
        }

		// Access the "flags" field
        if (mechanism_info.HasMember("flags") && mechanism_info["flags"].IsArray()) {
            const rapidjson::Value& flags = mechanism_info["flags"];

            int result = 0;
            if (flags[0].IsString()) {
                result = mechanismInfoFlagsMap[flags[0].GetString()];
            }

            for (rapidjson::SizeType i = 1; i < flags.Size(); ++i) {
                if (flags[i].IsString()) {
                    result = result | mechanismInfoFlagsMap[flags[i].GetString()];
                }
            }
            (**data)->flags = result;
        }//Flags end

    }
    return 0;
}


template <typename T>
unsigned int JsonParser<T>::populateData(CK_INFO*** data,const rapidjson::Value& additionalInfo){

	if (additionalInfo.HasMember("info") && additionalInfo["info"].IsObject()) {
        const rapidjson::Value& info = additionalInfo["info"];

		// Accessing 'cryptokiVersion' field
        if (info.HasMember("cryptokiVersion") && info["cryptokiVersion"].IsArray()) {
            const rapidjson::Value& crypto_version = info["cryptokiVersion"];

            if (crypto_version.Size() == 2 && crypto_version[0].IsInt() && crypto_version[1].IsInt()) {
                (**data)->cryptokiVersion.major = crypto_version[0].GetInt();
                (**data)->cryptokiVersion.minor = crypto_version[1].GetInt();
            }
        }

		//manufacturerID
        if (info.HasMember("manufacturerID") && info["manufacturerID"].IsString()) {
            strncpy((char*)(**data)->manufacturerID, info["manufacturerID"].GetString(), sizeof((**data)->manufacturerID));
        }

		// flags
        if (info.HasMember("flags") && info["flags"].IsString()) {
            (**data)->flags = 0;
        }

		// libraryDescription
        if (info.HasMember("libraryDescription") && info["libraryDescription"].IsString()) {
            strncpy((char*)(**data)->libraryDescription, info["libraryDescription"].GetString(), sizeof((**data)->libraryDescription));
        }

		// Accessing libraryVersion field
        if (info.HasMember("libraryVersion") && info["libraryVersion"].IsArray()) {
            const rapidjson::Value& library_version = info["libraryVersion"];

            if (library_version.Size() == 2 && library_version[0].IsInt() && library_version[1].IsInt()) {
                (**data)->libraryVersion.major = library_version[0].GetInt();
                (**data)->libraryVersion.minor = library_version[1].GetInt();
            }
        }

    }
    return 0;
}

template <typename T>
unsigned int JsonParser<T>::populateData(CK_SESSION_INFO*** data,const rapidjson::Value& additionalInfo){
	if (additionalInfo.HasMember("session_info") && additionalInfo["session_info"].IsObject()) {
        const rapidjson::Value& session_info = additionalInfo["session_info"];

        //slotID
        if (session_info.HasMember("slotID") && session_info["slotID"].IsInt()) {
           (**data)->slotID  = session_info["slotID"].GetInt();
        }

        //state
        if (session_info.HasMember("state") && session_info["state"].IsInt()) {
           (**data)->state  = session_info["state"].GetInt();
        }

        //ulDeviceError
        if (session_info.HasMember("ulDeviceError") && session_info["ulDeviceError"].IsInt()) {
           (**data)->ulDeviceError  = session_info["ulDeviceError"].GetInt();
        }

        //flags
        if (session_info.HasMember("flags") && session_info["flags"].IsInt()) {
           (**data)->flags  = session_info["flags"].GetInt();
        }
    }
    return 0;
}

std::vector<char> HexToBytes(const std::string& hex) {
    std::vector<char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        char byte = static_cast<char>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

template <typename T>
unsigned int JsonParser<T>::populateData(CK_BYTE*** data,const rapidjson::Value& additionalInfo){

    if (additionalInfo.HasMember("sign_output") && additionalInfo["sign_output"].IsObject()) {
        const rapidjson::Value& sign_output = additionalInfo["sign_output"];

        if ((**data)){
            if (sign_output.HasMember("data") && sign_output["data"].IsString()) {
                const char* sig_hexdata = sign_output["data"].GetString();
                std::cout<<"   sig_hexdata  :"<<strlen(sig_hexdata)<<std::endl;

                std::vector<char> sig_bytes = HexToBytes(sig_hexdata);
                std::cout<<"   sig_bytes  :"<<sig_bytes.size()<<std::endl;
                std::vector<char> arr(sig_bytes.size());
                for (unsigned int i = 0; i < sig_bytes.size(); i++) {
                    arr[i] = sig_bytes[i];
                }
                memcpy((void*)(**data), arr.data(),sig_bytes.size());
                return sig_bytes.size(); 
            }
        }//ifdata
        else{
                std::cout<<"--------In else in SignFinal---------------"<<std::endl;
                 if (sign_output.HasMember("len") && sign_output["len"].IsInt()) {
                    unsigned int sig_len = sign_output["len"].GetInt();
                    return sig_len;
                 }
                return 0;
        }
    }
}


template <typename T>
unsigned int JsonParser<T>::populateData(CK_ATTRIBUTE*** data,const rapidjson::Value& additionalInfo){

	if (additionalInfo.HasMember("attr_list") && additionalInfo["attr_list"].IsArray()) {
        const rapidjson::Value& attr_list = additionalInfo["attr_list"];

        for(rapidjson::SizeType i = 0;i < attr_list.Size(); ++i){
            const rapidjson::Value& attr = attr_list[i];
            unsigned int type;
            if (attr.HasMember("type") && attr["type"].IsInt()) {
                type = attr["type"].GetInt();
                std::cout<<" ---    (**data)->type)        "<<((**data)->type)<<std::endl;
                if (((**data)->type) != type)
                    continue;
            }

            if (((**data)->pValue) !=NULL){

                std::cout<<"--------(**data)->ulValueLen 2nd time ----"<<(**data)->ulValueLen <<std::endl;
                if (attr.HasMember("pValue") && attr["pValue"].IsString()) {
                    if (type == 3) {
                        const char* pValue  = attr["pValue"].GetString();
                        std::cout<<"------ pValue sie   :"<<strlen(pValue)<<std::endl;
                        size_t  len = strlen(pValue);
                        std::vector<unsigned char> arr(len);
                        for (unsigned int i = 0; i < len; ++i) {
                            arr[i] = pValue[i];
                        }

                        //const char* pValue  = attr["pValue"].GetString();
                        //memcpy((void*)(**data)->pValue,(void*)arr,(**data)->ulValueLen);
                        memcpy((void*)(**data)->pValue,arr.data(),(**data)->ulValueLen);
                    }else{

                        const char* pValue_hex  = attr["pValue"].GetString();

                        std::vector<char>pValue_bytes = HexToBytes(pValue_hex);

                        std::cout<<" pValue_bytes.size()   :"<<pValue_bytes.size()<<std::endl;

                        std::vector<char> arr(pValue_bytes.size());
                        for (unsigned int i = 0; i < pValue_bytes.size(); ++i) {
                            arr[i] = pValue_bytes[i];
                        }
                        std::cout<<"     before memcpy    :"<<std::endl;
                        //memcpy((void*)(**data)->pValue,(void*)(arr),pValue_bytes.size());
                        memcpy((void*)(**data)->pValue, arr.data(), pValue_bytes.size());
                    }

                }

                if (attr.HasMember("pValue") && attr["pValue"].IsInt()) {

                    std::cout<<"----------- inside IsINt() --------------"<<std::endl;
                    unsigned long* lValue = (unsigned long*)malloc(sizeof(unsigned long));
                    *lValue = attr["pValue"].GetInt();
                    std::cout<<"  INt pValue :"<<*lValue<<std::endl;
                    memcpy((**data)->pValue,(void*)lValue,sizeof(unsigned long) ); 

                }

                if (attr.HasMember("pValue") && attr["pValue"].IsArray()) {
                    const rapidjson::Value& pValue_list = attr["pValue"];
                    
                    std::vector<unsigned char> arr(pValue_list.Size());

                    for(int i = 0;i < pValue_list.Size(); ++i){
                       arr[i]  = pValue_list[i].GetInt();
                        std::cout<<arr[i] <<" ";
                    }
                    std::cout<<""<<std::endl;
                    //memcpy((**data)->pValue, (void*)arr,(**data)->ulValueLen );
                    memcpy((**data)->pValue, arr.data(), (**data)->ulValueLen );
                }

                if (attr.HasMember("pValue") && attr["pValue"].IsBool()) {
                    std::cout<<"----- pValue bool GetAttributeValue ----"<<std::endl;
                    unsigned char* pValue = (unsigned char*)malloc(sizeof(unsigned char) * (**data)->ulValueLen );
                    std::cout<< "    attr[pValue].GetBool() :"<<attr["pValue"].GetBool()<<std::endl;
                    *pValue = attr["pValue"].GetBool();
                    memcpy((**data)->pValue,(void*)pValue,(**data)->ulValueLen ); 
                }

            }else{
                    if (attr.HasMember("ulValueLen") && attr["ulValueLen"].IsInt()) {
                        int  ulValueLen = attr["ulValueLen"].GetInt();
                        (**data)->ulValueLen = ulValueLen;
                        std::cout<<"--------(**data)->ulValueLen ----"<<(**data)->ulValueLen <<std::endl;
                    }
            }
        }
    }
    return 0;
}
