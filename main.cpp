/*****************************************************************************
 main.cpp

 This file contains the main entry point to the PKCS #11 library. All it does
 is dispatch calls to the actual implementation and check for fatal exceptions
 on the boundary of the library.
 *****************************************************************************/

// The functions are exported library/DLL entry points
#define CRYPTOKI_EXPORTS

#include "cryptoki.h"
#include <stdio.h>
#include <cstring>
#include <string>

#ifdef _WIN32
#include <windows.h>
#endif

#include <iostream>
#include <cstdio> //Redirecting

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include "json_parser.h"
#include "json_builder.h"
#include "data_mapping.h"

#include "log4cxx/logger.h"
#include "log4cxx/xml/domconfigurator.h"

using namespace log4cxx;
using namespace log4cxx::helpers;
using namespace log4cxx::xml;
log4cxx::LoggerPtr logger; 

#ifdef _WIN32
#define EXPORT __declspec(dllexport)
#else
#define EXPORT
#endif


// Pointer holding list of funtions in PKCS11 library
CK_FUNCTION_LIST_PTR  ppFunctions = NULL;

void initialize_curl();
void performPostRequest( std::string&, const char* postData );
const char* get_loggerConfigFileName();
void init_ini_file();
void setLoginToken();


void initialize_logger(){
    //freopen("/dev/null", "w", stdout); //Redirecting
	const std::string logCfgPathname = get_loggerConfigFileName();
	DOMConfigurator::configure(logCfgPathname);  
	logger = log4cxx::Logger::getLogger("ec_pkcs11Client");
    LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call) {
		case DLL_PROCESS_ATTACH:
            init_ini_file();
			initialize_logger();
            setLoginToken();
			initialize_curl();
			break;
		default:
			break;
	}
	return TRUE;
}
#else
// Constructor function (called when the library is loaded)
void __attribute__((constructor)) init() {

    init_ini_file();
	initialize_logger();
    setLoginToken();
    initialize_curl();
}
#endif


// PKCS #11 function list
static CK_FUNCTION_LIST functionList =
{
	// Version information
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	// Function pointers
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};


// PKCS #11 initialisation function
extern "C" EXPORT CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	try
	{
	    LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	    return CKR_FUNCTION_FAILED;
	}

}

// PKCS #11 finalisation function
extern "C" EXPORT CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	try
	{
	    LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}


// Return information about the PKCS #11 module
extern "C" EXPORT CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	try
	{
	    LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        std::string readBuffer;
        JsonBuilder jsonBuilder("C_GetInfo");
        jsonBuilder.Serialize(); 
        std::string json_payload = jsonBuilder.GetJsonString(); 

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_INFO> jsonParser( readBuffer.c_str(),"C_GetInfo" );
        jsonParser.processJson(&pInfo);
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}


// Return the list of PKCS #11 functions
extern "C" EXPORT CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	try
	{

        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");

		if (ppFunctionList == NULL_PTR) return CKR_ARGUMENTS_BAD;

		*ppFunctionList = &functionList;

        return CKR_OK;

	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}


// Return a list of available slots
extern "C" EXPORT CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
     try
        {
            LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
            std::string readBuffer;
            JsonBuilder jsonBuilder("C_GetSlotList");
            jsonBuilder.AddItemToParams("tokenPresent",1);
            //jsonBuilder.AddItemToParams("tokenPresent",tokenPresent);
            jsonBuilder.Serialize(); 
            std::string json_payload = jsonBuilder.GetJsonString(); 

            LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
            performPostRequest( readBuffer, json_payload.c_str() );
            LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

            JsonParser<CK_SLOT_ID> jsonParser( readBuffer.c_str(),"C_GetSlotList" );
            unsigned int s_count = jsonParser.processJson(&pSlotList);
            *pulCount = s_count;
                
            return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about a slot
extern "C" EXPORT CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        std::string readBuffer;

        JsonBuilder jsonBuilder("C_GetSlotInfo");
		jsonBuilder.AddItemToParams("slotId",slotID);
		jsonBuilder.Serialize(); 
		std::string json_payload = jsonBuilder.GetJsonString(); 

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_SLOT_INFO> jsonParser( readBuffer.c_str(),"C_GetSlotInfo" );

        jsonParser.processJson(&pInfo);

        std::cout<<"-----slot description----" <<pInfo->slotDescription <<std::endl;
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Return information about a token in a slot
extern "C" EXPORT CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		std::string readBuffer;

        JsonBuilder jsonBuilder("C_GetTokenInfo");
        jsonBuilder.AddItemToParams("slotId",slotID);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_TOKEN_INFO> jsonParser( readBuffer.c_str(),"C_GetTokenInfo" );
        jsonParser.processJson(&pInfo);

        return CKR_OK;
    }
    catch (...)
    {
        printf("An Exception occurred in %s",__func__);
    }
	return CKR_FUNCTION_FAILED;
}

// Return the list of supported mechanisms for a given slot
extern "C" EXPORT CK_RV C_GetMechanismList(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");

        if (pMechanismList){
            MechanismList& instance = MechanismList::getInstance();
            unsigned int len = instance.getLength();
            unsigned long* array  = instance.getArray();
            for( int i =0; i<len; i++)
            {
                pMechanismList[i] = array[i]; 
            }
            *pulCount = len; 
            return CKR_OK;
        }
        else{

            std::string readBuffer;
            JsonBuilder jsonBuilder("C_GetMechanismList");
            jsonBuilder.AddItemToParams("slotId",slotID);
            jsonBuilder.Serialize();
            std::string json_payload = jsonBuilder.GetJsonString();

            LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
            performPostRequest( readBuffer, json_payload.c_str() );
            LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

            JsonParser<CK_MECHANISM_TYPE> jsonParser( readBuffer.c_str(),"C_GetMechanismList" );

            jsonParser.processJson(&pulCount);

            std::cout<<"-----pulCount----" <<*pulCount <<std::endl;

            return CKR_OK;
        }
	}//try
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Return more information about a mechanism for a given slot
extern "C" EXPORT CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        std::string readBuffer;
        std::string m_type = getCKMName( type );

        if (strcmp(m_type.c_str(),"Unknown")==0){
            return CKR_OK;
        }

        JsonBuilder jsonBuilder("C_GetMechanismInfo");
        jsonBuilder.AddItemToParams("slotId",slotID);
        jsonBuilder.AddItemToParams("type",m_type.c_str());
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        //LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_MECHANISM_INFO> jsonParser( readBuffer.c_str(),"C_GetMechanismInfo" );
        jsonParser.processJson(&pInfo);
       
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise the token in the specified slot
extern "C" EXPORT CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen, CK_UTF8CHAR_PTR pLabel)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise the user PIN
extern "C" EXPORT CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Change the PIN
extern "C" EXPORT CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin, CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	try
	{
         LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Open a new session to the specified slot
extern "C" EXPORT CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication, CK_NOTIFY notify, CK_SESSION_HANDLE_PTR phSession)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		std::string readBuffer;

        JsonBuilder jsonBuilder("C_OpenSession");
        jsonBuilder.AddItemToParams("slotId",slotID);
        jsonBuilder.AddItemToParams("flags",flags);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_OpenSession" );
        jsonParser.processJson(&phSession);

        std::cout<<"----- utc time ----" <<*phSession <<std::endl;

        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Close the given session
extern "C" EXPORT CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Close all open sessions
extern "C" EXPORT CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Retrieve information about the specified session
extern "C" EXPORT CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		std::string readBuffer;

        JsonBuilder jsonBuilder("C_GetSessionInfo");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_SESSION_INFO> jsonParser( readBuffer.c_str(),"C_GetSessionInfo" );

        jsonParser.processJson(&pInfo);

        std::cout<<"-----Session handle----" <<pInfo->flags <<std::endl;


        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Determine the state of a running operation in a session
extern "C" EXPORT CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG_PTR pulOperationStateLen)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Set the operation sate in a session
extern "C" EXPORT CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState, CK_ULONG ulOperationStateLen, CK_OBJECT_HANDLE hEncryptionKey, CK_OBJECT_HANDLE hAuthenticationKey)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Login on the token in the specified session
extern "C" EXPORT CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");

        std::string readBuffer;
		JsonBuilder jsonBuilder("C_Login");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.AddItemToParams("userType",userType);
        jsonBuilder.AddItemToParams("pin",(const char*)pPin, ulPinLen);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_Login" );
        jsonParser.processJson(NULL);

        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}
	return CKR_FUNCTION_FAILED;
}

// Log out of the token in the specified session
extern "C" EXPORT CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Create a new object on the token in the specified session using the given attribute template
extern "C" EXPORT CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Create a copy of the object with the specified handle
extern "C" EXPORT CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Destroy the specified object
extern "C" EXPORT CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Determine the size of the specified object
extern "C" EXPORT CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

void printvalues( CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    // Iterate through each attribute in the array
    for (CK_ULONG i = 0; i < ulCount; ++i)
    {
        CK_ATTRIBUTE attr = pTemplate[i];

        CK_OBJECT_CLASS* classValue = NULL;
        CK_BBOOL* tokenValue = NULL;
        CK_BYTE* idValue = NULL;
        unsigned char *id = NULL;

        // Depending on the attribute type, handle its value appropriately
        switch (attr.type)
        {
            case CKA_CLASS:
                std::cout << "Attribute type CKA_CLASS: " << std::endl;
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

                classValue = static_cast<CK_OBJECT_CLASS*>(attr.pValue);
                std::cout << "Attribute Value (Class): " << *classValue << std::endl;
                break;
            case CKA_TOKEN:
                std::cout << "Attribute type CKA_TOKEN: " << std::endl;
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

                tokenValue = static_cast<CK_BBOOL*>(attr.pValue);
                std::cout << "Attribute Value (Token): " << *tokenValue << std::endl;
                break;
            case CKA_PRIVATE:
                std::cout << "Attribute type CKA_PRIVATE: " << std::endl;
                break;
            case CKA_LABEL:
                std::cout << "Attribute type CKA_LABEL: " << std::endl;
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

				id = (unsigned char*)malloc(attr.ulValueLen);
                idValue = static_cast<CK_BYTE*>(attr.pValue);
                std::cout << "Attribute Value (ID): ";
                for (size_t j = 0; j < attr.ulValueLen; ++j) {
                    std::cout << static_cast<int>(idValue[j])<<" ";
                    id[j] = static_cast<int>(idValue[j]);
                }
                std::cout << std::endl;
                std::cout<< "----label ---"<< id <<std::endl;

                break;
			 case CKA_MODULUS:
                std::cout << "Attribute type CKA_MODULUS: " << std::endl;

                if (attr.pValue)
                {
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

                id = (unsigned char*)malloc(attr.ulValueLen);
                idValue = static_cast<CK_BYTE*>(attr.pValue);
                std::cout << "Attribute Value (MODULUS): ";
                for (size_t j = 0; j < attr.ulValueLen; ++j) {
                    std::cout << static_cast<int>(idValue[j]);
                    id[j] = static_cast<int>(idValue[j]);
                }
                std::cout << std::endl;
                std::cout<< "----modulus---"<< id <<std::endl;
                }

                break;
            case CKA_SIGN:
                std::cout << "Attribute type CKA_SIGN: " << std::endl;
                break;
            case CKA_ID:
                std::cout << "Attribute type CKA_ID: " << std::endl;
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

                id = (unsigned char*)malloc(attr.ulValueLen);
                idValue = static_cast<CK_BYTE*>(attr.pValue);
                std::cout << "Attribute Value (ID): ";
                for (size_t j = 0; j < attr.ulValueLen; ++j) {
                    std::cout << static_cast<int>(idValue[j]);
                    id[j] = static_cast<int>(idValue[j]);
                }
                std::cout << std::endl;
                std::cout<< "----id---"<< id <<std::endl;
                break;

            // Add more cases for other attribute types as needed
            default:
                // Handle unknown attribute types
                std::cout << "Unknown attribute type" << std::endl;
                break;
        }
    }
}


// Retrieve the specified attributes for the given object
extern "C" EXPORT CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		//printvalues(pTemplate,ulCount);
		std::string readBuffer;

        std::cout<<"----- C_GetAttributeValue  ulCount --- "<<ulCount<<std::endl;

        JsonBuilder jsonBuilder("C_GetAttributeValue");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.AddItemToParams("obj_handle",hObject);

        // Iterate through each attribute in the array
        for (CK_ULONG i = 0; i < ulCount; ++i)
        {
            CK_ATTRIBUTE attr = pTemplate[i];

            switch (attr.type)
            {
                case CKA_CLASS:  
                    std::cout << "Attribute type CKA_CLASS: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_CLASS);
                    break;
                case CKA_KEY_TYPE:
                    std::cout << "Attribute type CKA_KEY_TYPE: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_KEY_TYPE);
                    break;
                case CKA_TOKEN:
                    std::cout << "Attribute type CKA_TOKEN: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_TOKEN);
                    break;
                case CKA_ID:
                    std::cout << "Attribute type CKA_ID: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_ID);
                    break;
                case CKA_SIGN:
                    std::cout << "Attribute type CKA_SIGN: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_SIGN);
                    break;
                case CKA_LABEL:
                    std::cout << "Attribute type CKA_LABEL: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_LABEL);
                    break;
                case CKA_PRIVATE:
                    std::cout << "Attribute type CKA_PRIVATE: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_PRIVATE);
                    break;
                case CKA_SENSITIVE:
                    std::cout << "Attribute type CKA_SENSITIVE: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_SENSITIVE);
                    break;
                case CKA_TRUSTED:
                    std::cout << "Attribute type CKA_TRUSTED: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_TRUSTED);
                    break;
                case CKA_ALWAYS_AUTHENTICATE:
                    std::cout << "Attribute type CKA_ALWAYS_AUTHENTICATE: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_ALWAYS_AUTHENTICATE);
                    break;
                case CKA_PUBLIC_EXPONENT:
                    std::cout << "Attribute type CKA_PUBLIC_EXPONENT: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_PUBLIC_EXPONENT);
                    break;
                case CKA_VALUE:
                    std::cout << "Attribute type CKA_VALUE: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_VALUE);
                    break;
                case CKA_MODULUS:
                    std::cout << "Attribute type CKA_MODULUS: " << std::endl;
                    jsonBuilder.AddItemToTemplateArray(CKA_MODULUS);
                    break;
                default:
                    std::cout<<"---- C_GetAttributeValue -- Unknown attribute type -:"<<attr.type<<std::endl;
                    jsonBuilder.AddItemToTemplateArray(attr.type);
            }
        }
        jsonBuilder.AddTemplateArrayToParams();
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_ATTRIBUTE> jsonParser( readBuffer.c_str(),"C_GetAttributeValue" );

        for (CK_ULONG i = 0; i < ulCount; ++i)
        {
            CK_ATTRIBUTE_PTR pAttr = (pTemplate + i);
            jsonParser.processJson( &pAttr );
        }

		//printvalues(pTemplate,ulCount);
	    std::cout<<"---------------RETURNED GetAttributeValue -----------START-------------"<<std::endl;
        
        // Iterate through each attribute in the array
        for (CK_ULONG i = 0; i < ulCount; ++i)
        {
            CK_ATTRIBUTE attr = pTemplate[i];

            std::cout<<"---Attribute type ----:"<<attr.type<<std::endl;
            std::cout<<"----Attribute len ----:"<<attr.ulValueLen<<std::endl;

            if ( (attr.type == CKA_VALUE) || (attr.type == CKA_ID)||(attr.type == CKA_LABEL)||(attr.type == CKA_MODULUS)){
                if (attr.pValue != NULL){
                    printf("Value: ");
                    // Print each character up to ulValueLen
                    for (CK_ULONG i = 0; i < attr.ulValueLen; i++) {
                        printf("%c", ((char*)attr.pValue)[i]);
                    }
                    printf("\n");
                }
            }
        }
        
        std::cout<<"---------------RETURNED GetAttributeValue -----------END-------------"<<std::endl;	
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}


// Change or set the value of the specified attributes on the specified object
extern "C" EXPORT CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    try
    {
        printf("\n Inside function %s",__func__);return CKR_OK;
    }
    catch (...)
    {
        printf("An Exception occurred in %s",__func__);
    }

    return CKR_FUNCTION_FAILED;
} 

void processTemplateAttr( JsonBuilder &jBuilder, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    std::unordered_map<unsigned long,unsigned long> attr_map; 
    std::unordered_map<unsigned long,unsigned char*> attr_map1; 

    // Iterate through each attribute in the array
    for (CK_ULONG i = 0; i < ulCount; ++i)
    {
        CK_ATTRIBUTE attr = pTemplate[i];
        attr_map.clear();

        CK_OBJECT_CLASS* classValue = NULL;
        CK_OBJECT_CLASS* keyTypeValue = NULL;
        CK_BBOOL* tokenValue = NULL;
        CK_BYTE* idValue = NULL;
        unsigned char* id = NULL;

        // Depending on the attribute type, handle its value appropriately
        switch (attr.type)
        {
            case CKA_CLASS:
                std::cout << "Attribute type CKA_CLASS: " << std::endl;
                classValue = static_cast<CK_OBJECT_CLASS*>(attr.pValue);
                attr_map.insert({CKA_CLASS, *classValue });
                jBuilder.AddTupleToTemplateArray(attr_map );
                break;
            case CKA_KEY_TYPE:
                std::cout << "Attribute type CKA_KEY_TYPE: " << std::endl;
                keyTypeValue = static_cast<CK_OBJECT_CLASS*>(attr.pValue);
                attr_map.insert({CKA_KEY_TYPE, *keyTypeValue });
                jBuilder.AddTupleToTemplateArray(attr_map );
                break;
            case CKA_TOKEN:
                std::cout << "Attribute type CKA_TOKEN: " << std::endl;
                tokenValue = static_cast<CK_BBOOL*>(attr.pValue);
                //attr_map.insert({CKA_TOKEN, 1 });
                attr_map.insert({CKA_TOKEN, *tokenValue });
                jBuilder.AddTupleToTemplateArray(attr_map );
                break;

/*
            case CKA_PRIVATE:
                std::cout << "Attribute type CKA_PRIVATE: " << std::endl;
                break;
            case CKA_LABEL:
                std::cout << "Attribute type CKA_LABEL: " << std::endl;
                break;
            case CKA_SIGN:
                std::cout << "Attribute type CKA_SIGN: " << std::endl;
                break;
*/
            case CKA_ID:
                std::cout << "Attribute type CKA_ID: " << std::endl;
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

                id = (unsigned char*)malloc(attr.ulValueLen);
                idValue = static_cast<CK_BYTE*>(attr.pValue);
                std::cout << "Attribute Value (ID): ";
                for (size_t j = 0; j < attr.ulValueLen; ++j) {
                    std::cout << static_cast<unsigned char>(idValue[j]) << " ";
                    id[j] = static_cast<unsigned char>(idValue[j]);
                }
                std::cout<<"----printing id ---"<<id<<std::endl;
                attr_map1.insert({CKA_ID, id});
                jBuilder.AddTupleToTemplateArray(attr_map1 );
                std::cout << std::endl;
                break;

            case CKA_SUBJECT:
                std::cout << "Attribute type CKA_SUBJECT: " << std::endl;
                std::cout << "Attribute Length: " << attr.ulValueLen << std::endl;

                id = (unsigned char*)malloc(attr.ulValueLen);
                idValue = static_cast<CK_BYTE*>(attr.pValue);
                std::cout << "Attribute Value (SUBJECT): ";
                for (size_t j = 0; j < attr.ulValueLen; ++j) {
                    std::cout << static_cast<unsigned char>(idValue[j]) << " ";
                    id[j] = static_cast<unsigned char>(idValue[j]);
                }
                std::cout<<"----printing subject ---"<<id<<std::endl;
                attr_map1.insert({CKA_SUBJECT, id});
                jBuilder.AddTupleToTemplateArray(attr_map1 );
                std::cout << std::endl;
                break;
            // Add more cases for other attribute types as needed
            default:
                // Handle unknown attribute types
                std::cout << "Unknown attribute type ---- :"<<attr.type << std::endl;
                break;
        }
    }//Forloop
    jBuilder.AddTemplateArrayToParams();
}


// Initialise object search in the specified session using the specified attribute template as search parameters
extern "C" EXPORT CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		std::string readBuffer;

        std::cout<<"----- FindObjectsInit ulCount --- "<<ulCount<<std::endl;

        JsonBuilder jsonBuilder("C_FindObjectsInit");
        jsonBuilder.AddItemToParams("session",hSession);

        processTemplateAttr(jsonBuilder, pTemplate, ulCount);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

		JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_FindObjectsInit" );
        jsonParser.processJson(NULL);

        return CKR_OK;
        
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Continue the search for objects in the specified session
extern "C" EXPORT CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		std::string readBuffer;

		JsonBuilder jsonBuilder("C_FindObjects");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.AddItemToParams("maxObjCount",ulMaxObjectCount);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_FindObjects" );
        unsigned int count = jsonParser.processJson(&phObject);

        *pulObjectCount = count;
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Finish searching for objects
extern "C" EXPORT CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
		std::string readBuffer;

        JsonBuilder jsonBuilder("C_FindObjectsFinal");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

        JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_FindObjectsFinal" );
        jsonParser.processJson(NULL);

        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise encryption using the specified object and mechanism
extern "C" EXPORT CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single operation encryption operation in the specified session
extern "C" EXPORT CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Feed data to the running encryption operation in a session
extern "C" EXPORT CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the encryption operation
extern "C" EXPORT CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise decryption using the specified object
extern "C" EXPORT CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hObject)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single operation decryption in the given session
extern "C" EXPORT CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Feed data to the running decryption operation in a session
extern "C" EXPORT CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the decryption operation
extern "C" EXPORT CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG_PTR pDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise digesting using the specified mechanism in the specified session
extern "C" EXPORT CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Digest the specified data in a one-pass operation and return the resulting digest
extern "C" EXPORT CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running digest operation
extern "C" EXPORT CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running digest operation by digesting a secret key with the specified handle
extern "C" EXPORT CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the digest operation in the specified session and return the digest
extern "C" EXPORT CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a signing operation using the specified key and mechanism
extern "C" EXPORT CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");

        std::string readBuffer;
        JsonBuilder jsonBuilder("C_SignInit");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.AddItemToParams("mechanism",pMechanism->mechanism);
        jsonBuilder.AddItemToParams("obj_handle",hKey);

        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

		JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_SignInit" );
        jsonParser.processJson(NULL);

        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Sign the data in a single pass operation
extern "C" EXPORT CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");

        std::string readBuffer;
        JsonBuilder jsonBuilder("C_Sign");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.AddItemToParams("data_part",(const char*)pData, ulDataLen);

        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

		JsonParser<CK_BYTE> jsonParser( readBuffer.c_str(),"C_Sign" );
        unsigned int sig_len = jsonParser.processJson(&pSignature);
        *pulSignatureLen = sig_len;
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running signing operation with additional data
extern "C" EXPORT CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        std::cout<<"    ulPartLen  "<<ulPartLen<<std::endl;
        std::cout<<"    ulPartLen sizeof  :"<<sizeof(*pPart)<<std::endl;
        void * arr = malloc(ulPartLen);  
        memcpy( arr,(void*)pPart,ulPartLen);

		printf("Value1: ");
        for (CK_ULONG i = 0; i < ulPartLen; i++) {
            printf("%c", ((char*)arr)[i]);
        }
        printf("\n");

        std::string readBuffer;
        JsonBuilder jsonBuilder("C_SignUpdate");
        jsonBuilder.AddItemToParams("session",hSession);
        //jsonBuilder.AddItemToParams("data_part",(const char*)arr);
        jsonBuilder.AddItemToParams("data_part",(const char*)arr, ulPartLen);

        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);

		JsonParser<CK_SESSION_HANDLE> jsonParser( readBuffer.c_str(),"C_SignUpdate" );
        jsonParser.processJson(NULL);
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise a running signing operation and return the signature
extern "C" EXPORT CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
        LOG4CXX_INFO(logger, __func__ << ": --------Executing --------");
        std::cout<<"----pulSignatureLen-----"<<*pulSignatureLen<<std::endl;

        std::string readBuffer;
        JsonBuilder jsonBuilder("C_SignFinal");
        jsonBuilder.AddItemToParams("session",hSession);
        jsonBuilder.Serialize();
        std::string json_payload = jsonBuilder.GetJsonString();

        LOG4CXX_DEBUG(logger, __func__ << ": Request :" << json_payload);
        performPostRequest( readBuffer, json_payload.c_str() );
        LOG4CXX_DEBUG(logger, __func__ << ": Response :" << readBuffer);
		JsonParser<CK_BYTE> jsonParser( readBuffer.c_str(),"C_SignFinal" );

        unsigned int sig_len = jsonParser.processJson(&pSignature);
        *pulSignatureLen = sig_len;
        std::cout<<"----returned pulSignatureLen sig_len :"<<sig_len<<std::endl;
        
        printf("Value: ");
        for (CK_ULONG i = 0; i < *pulSignatureLen; i++) {
            printf("%c", ((char*)pSignature)[i]);
        }
        printf("\n");

        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a signing operation that allows recovery of the signed data
extern "C" EXPORT CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single part signing operation that allows recovery of the signed data
extern "C" EXPORT CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a verification operation using the specified key and mechanism
extern "C" EXPORT CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
        int err = 0;
        printf("\n Inside function %s",__func__);
        return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single pass verification operation
extern "C" EXPORT CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running verification operation with additional data
extern "C" EXPORT CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Finalise the verification operation and check the signature
extern "C" EXPORT CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Initialise a verification operation the allows recovery of the signed data from the signature
extern "C" EXPORT CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Perform a single part verification operation and recover the signed data
extern "C" EXPORT CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen, CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part encryption and digesting operation
extern "C" EXPORT CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part decryption and digesting operation
extern "C" EXPORT CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pDecryptedPart, CK_ULONG_PTR pulDecryptedPartLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part signing and encryption operation
extern "C" EXPORT CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Update a running multi-part decryption and verification operation
extern "C" EXPORT CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Generate a secret key using the specified mechanism
extern "C" EXPORT CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Generate a key-pair using the specified mechanism
extern "C" EXPORT CK_RV C_GenerateKeyPair
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_ATTRIBUTE_PTR pPublicKeyTemplate, 
	CK_ULONG ulPublicKeyAttributeCount, 
	CK_ATTRIBUTE_PTR pPrivateKeyTemplate, 
	CK_ULONG ulPrivateKeyAttributeCount,
	CK_OBJECT_HANDLE_PTR phPublicKey, 
	CK_OBJECT_HANDLE_PTR phPrivateKey
)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Wrap the specified key using the specified wrapping key and mechanism
extern "C" EXPORT CK_RV C_WrapKey
(
	CK_SESSION_HANDLE hSession,
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hWrappingKey, 
	CK_OBJECT_HANDLE hKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG_PTR pulWrappedKeyLen
)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Unwrap the specified key using the specified unwrapping key
extern "C" EXPORT CK_RV C_UnwrapKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hUnwrappingKey, 
	CK_BYTE_PTR pWrappedKey, 
	CK_ULONG ulWrappedKeyLen,
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Derive a key from the specified base key
extern "C" EXPORT CK_RV C_DeriveKey
(
	CK_SESSION_HANDLE hSession, 
	CK_MECHANISM_PTR pMechanism, 
	CK_OBJECT_HANDLE hBaseKey, 
	CK_ATTRIBUTE_PTR pTemplate, 
	CK_ULONG ulCount, 
	CK_OBJECT_HANDLE_PTR phKey
)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Seed the random number generator with new data
extern "C" EXPORT CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Generate the specified amount of random data
extern "C" EXPORT CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Legacy function
extern "C" EXPORT CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Legacy function
extern "C" EXPORT CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	try
	{
printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

// Wait or poll for a slot even on the specified slot
extern "C" EXPORT CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	try
	{
        printf("\n Inside function %s",__func__);return CKR_OK;
	}
	catch (...)
	{
		printf("An Exception occurred in %s",__func__);
	}

	return CKR_FUNCTION_FAILED;
}

