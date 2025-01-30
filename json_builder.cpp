#include "json_builder.h" 
#include "base64.h"


// Function to encode binary data as Base64
std::string base64Encode(const unsigned char* data, size_t len) {
	
	std::string base64EncodedData = base64_encode(data, len);
	return base64EncodedData;
}


    void JsonBuilder::AddItemToParams( const char* key1, unsigned int value)
    {
        rapidjson::Value slotIdObject(rapidjson::kObjectType);

        rapidjson::Value key(key1,document.GetAllocator());
        rapidjson::Value val(value);
        slotIdObject.AddMember(key, val, document.GetAllocator());

        params.PushBack(slotIdObject, document.GetAllocator());
    }


    void JsonBuilder::AddItemToParams( const char* key1, const char* value, unsigned long len)
    {

        rapidjson::Value slotIdObject(rapidjson::kObjectType);

        rapidjson::Value key(key1,document.GetAllocator());
        if (len == 0){
            rapidjson::Value val(value, document.GetAllocator());
            slotIdObject.AddMember(key, val, document.GetAllocator());
        }else{
            rapidjson::Value val;
			std::string base64EncodedData = base64Encode((const unsigned char*)value, len);
            val.SetString(base64EncodedData.c_str(), base64EncodedData.length(), document.GetAllocator());
            slotIdObject.AddMember(key, val, document.GetAllocator());
        }
        params.PushBack(slotIdObject, document.GetAllocator());
    }


	void JsonBuilder::AddTupleToTemplateArray( std::unordered_map<unsigned long, unsigned char*>& attr_map )
    {
        rapidjson::Value tuple1(rapidjson::kArrayType);

        for(const auto& key_value: attr_map) {
            unsigned int key = key_value.first;
            char* value = (char*)key_value.second;
            std::cout << key << " - " << value << std::endl;
            size_t len = strlen(value);

            rapidjson::Value key1(key);
            rapidjson::Value val;
			std::string base64EncodedData = base64Encode((const unsigned char*)value, len);
            val.SetString(base64EncodedData.c_str(), base64EncodedData.length(), document.GetAllocator());

            tuple1.PushBack(key1, document.GetAllocator());
            tuple1.PushBack(val, document.GetAllocator());
            templateArray.PushBack(tuple1, document.GetAllocator());
        }
    }


    void JsonBuilder::AddTupleToTemplateArray( std::unordered_map<unsigned long, unsigned long>& attr_map )
    {
        rapidjson::Value tuple1(rapidjson::kArrayType);

		for(const auto& key_value: attr_map) {
			unsigned int key = key_value.first;
			unsigned int value = key_value.second;    
			std::cout << key << " - " << value << std::endl;

			rapidjson::Value key1(key);
			rapidjson::Value val(value);

			tuple1.PushBack(key1, document.GetAllocator());
			tuple1.PushBack(val, document.GetAllocator());
        	templateArray.PushBack(tuple1, document.GetAllocator());
		}
    }


    void JsonBuilder::AddItemToTemplateArray(unsigned int attrType) 
    {
        rapidjson::Value val(attrType);
        templateArray.PushBack(val,document.GetAllocator());
    }


    void JsonBuilder::AddTemplateArrayToParams()
    {
        rapidjson::Value templateObject(rapidjson::kObjectType);
        templateObject.AddMember("template",templateArray,document.GetAllocator());
        params.PushBack(templateObject, document.GetAllocator());
    }


    void JsonBuilder::Serialize(){
        rapidjson::Value api(apiName.c_str(),document.GetAllocator()); 
        data.AddMember("API", api, document.GetAllocator());
        data.AddMember("params", params, document.GetAllocator());
        document.AddMember("data", data, document.GetAllocator());
    }


    std::string JsonBuilder::GetJsonString() const{
        rapidjson::StringBuffer buffer;
        rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
        document.Accept(writer);
        return buffer.GetString();
    }
	

//#endif // JSON_BUILDER_H
