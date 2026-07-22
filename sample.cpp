#include <iostream>
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

int main(void){
  std::string sampleJson = R"({
    "project": "CloudGuard-CI",
    "status": "active",
    "scanner_version": 1.0
    })";
  json data = json::parse(sampleJson);
  std::cout << "Project: " << data["project"] << "\n";
  std::cout << "Status: " << data["status"] << "\n";
  return 0;
}
