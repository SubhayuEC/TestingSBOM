#ifndef JSON_BUILDER_H
#define JSON_BUILDER_H

#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"
#include <iostream>
#include <vector>
#include <unordered_map>

class JsonBuilder {
public:
    JsonBuilder(std::string name ): apiName(name),data(rapidjson::kObjectType),params(rapidjson::kArrayType),templateArray(rapidjson::kArrayType){
        document.SetObject();
    }
    void  AddItemToParams( const char* key1, unsigned int value);
    void  AddItemToParams( const char* key1, const char* value, unsigned long len =0);
    void  AddTemplateArrayToParams();
    void  AddTupleToTemplateArray(std::unordered_map<unsigned long, unsigned long>& attr_map );
    void  AddTupleToTemplateArray(std::unordered_map<unsigned long, unsigned char*>& attr_map );
    void  AddItemToTemplateArray(unsigned int attrType);
    void Serialize();

    std::string GetJsonString() const; 
	
private:
	rapidjson::Document document;
    rapidjson::Value data;
    rapidjson::Value params;
    rapidjson::Value templateArray;
    std::string apiName;
};

#endif // JSON_BUILDER_H
