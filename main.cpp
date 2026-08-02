#include <iostream>
#include <fstream>
#include <vector>
#include <memory>
#include "json.hpp"

using json = nlohmann::json;

struct Finding{
  std::string resourceAddress;
  std::string ruleName;
  std::string severity;
  std::string message;
};

class Rule{
public:
  virtual ~Rule() = default;
  virtual std::string getRuleName() const = 0;
  virtual std::string getResourceType() const = 0;
  virtual bool evaluate(const json& resource, Finding& outFinding) const = 0;
};

class s3PublicBucketRule : public Rule{
public:
  std::string getRuleName() const override{
    return "S3-001: Public S3 Bucket Detected";
  }
  std::string getResourceType() const override{
    return "aws_s3_bucket";
  } 
  bool evaluate(const json& resource, Finding& outFinding) const override{
    if(resource.contains("change") && resource["change"].contains("after") && resource["change"]["after"].contains("acl")){
      std::string acl = resource["change"]["after"]["acl"];
      if(acl == "public-read" || acl == "public-read-write"){
        outFinding.resourceAddress = resource["address"];
        outFinding.ruleName = getRuleName();
        outFinding.severity = "HIGH";
        outFinding.message = "[FAIL] Security Risk Found!\nResource: " + outFinding.resourceAddress + "\nIssue: Bucket ACL is set to '" + acl + "' (it is publicly accessible to the internet!)\n\n";
        return true;
      }
    }
    return false;
  }
};

class OpenSecurityGroupRule : public Rule{
public:
  std::string getRuleName() const override{
    return "SG-001: Overly Permissive Security Group Detected";
  }
  std::string getResourceType() const override{
    return "aws_security_group";
  }
  bool evaluate(const json& resource, Finding& outFinding) const override{
    if(resource.contains("change") && resource["change"].contains("after") && resource["change"]["after"].contains("ingress")){
      const auto& ingress = resource["change"]["after"]["ingress"];
      for(const auto& rule : ingress){
        for(const auto& cidr : rule["cidr_blocks"]){
          int from = rule["from_port"];
          int to = rule["to_port"];
          if(cidr == "0.0.0.0/0" && ((from<= 22 && 22 <= to) || (from <= 80 && 80 <= to))){
            outFinding.resourceAddress = resource["address"];
            outFinding.ruleName = getRuleName();
            outFinding.severity = "HIGH";
            outFinding.message = "[FAIL] Security Risk Found!\nResource: " + outFinding.resourceAddress + "\nIssue: Security Group is open.";
            return true;
          }
        }
      }
    }
    return false;
  }
};

class Scanner{
public:
  std::vector<std::unique_ptr<Rule>> rules;
  void addRule(std::unique_ptr<Rule> rule){
    rules.push_back(std::move(rule));
  }
  std::vector<Finding> runScan(const json& planData){
    std::vector <Finding> findings;
    for(const auto& res : planData["resource_changes"]){
      for(const auto& rule : rules){
        if(res.contains("type") && rule->getResourceType() == res["type"]){
          Finding f;
          if(rule->evaluate(res, f)){
            findings.push_back(f);
          }
        }
      }
    }
    return findings;
  }
};

int main(int argc, char* argv[]) {
  std::string tfplan = (argc > 1) ? argv[1] : "tfplan.json";
  std::ifstream file(tfplan);
  if(!file.is_open()){
    std::cerr << "[ERROR] Could not open "<< tfplan << "!\n";
    return 1;
  }

  json planData;
  file >> planData;
  
  Scanner scanner;
  
  scanner.addRule(std::make_unique<s3PublicBucketRule>());
  scanner.addRule(std::make_unique<OpenSecurityGroupRule>());

  std::vector<Finding> findings = scanner.runScan(planData);
  for(const auto& f : findings){
    std::cout << f.message;
  }
  return findings.empty() ? 0 : 1;
}
