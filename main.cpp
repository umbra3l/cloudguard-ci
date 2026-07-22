#include <iostream>
#include <fstream>
#include "json.hpp"

using json = nlohmann::json;

int main() {
  std::ifstream file("tfplan.json");
  if(!file.is_open()){
    std::cerr << "[ERROR] Could not open tfplan.json!\n";
    return -1;
  }

  json planData;
  file >> planData;
  
  int vulnerabilitiesFound = 0;

  std::cout << "====================================\n";
  std::cout << "CloudGuard-CI Infrastructure Scanner\n";
  std::cout << "====================================\n";
  
  for(const auto& res : planData["resource_changes"]) {
    std::string resType = res["type"];
    std::string address = res["address"];

    if(resType == "aws_s3_bucket"){
      std::string acl = res["change"]["after"]["acl"];

      if(acl == "public-read" || acl == "public-read-write"){
        std::cout << "[FAIL] Security Risk Found!\n";
        std::cout << "Resource: " << address << "\n";
        std::cout << "Issue: Bucket ACL is set to '" << acl << "' (it is publicly accessible to the internet!)\n\n";
        vulnerabilitiesFound++;
      } else{
        std::cout << "[PASS] " << address << " (ACL: " << acl << ")\n\n";
      }
    }
  }
  
  if(vulnerabilitiesFound > 0){
    std::cout << "Scan Result: FAILED (" <<vulnerabilitiesFound << " security vulnerability found)\n";
    return -1;
  }

  std::cout << "Scan Result: PASSED (All resources compliant)\n";
  return 0;
}
