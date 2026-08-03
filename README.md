# CloudGuard-CI

A high-performance, object-oriented Static Infrastructure-as-Code (IaC) Security Scanner written in C++17.

CloudGuard-CI parses Terraform plan JSON files (`tfplan.json`) **before** cloud provisioning occurs, evaluating planned resource changes against security compliance rules. If a violation is found, the scanner outputs a structured finding and exits with code `1` to fail CI/CD pipelines automatically.

---

## Features

- Parses Terraform plan JSON (`terraform show -json` output)
- Extensible rule engine built on C++ polymorphism
- Fails CI/CD pipelines on security violations via exit code
- Accepts a custom plan file path via CLI argument

### Security Rules

| Rule ID | Resource Type | Description |
|---------|--------------|-------------|
| S3-001 | `aws_s3_bucket` | Detects publicly accessible S3 buckets (`public-read` / `public-read-write` ACL) |
| SG-001 | `aws_security_group` | Detects ingress rules open to `0.0.0.0/0` on port 22 (SSH) or port 80 (HTTP) |

---

## Requirements

- g++ with C++17 support
- [nlohmann/json](https://github.com/nlohmann/json) (included as `json.hpp`)

---

## CI/CD Integration

CloudGuard-CI runs automatically on every push via GitHub Actions. If any security violation is found, the pipeline fails — blocking unsafe infrastructure from being deployed.

![GitHub Actions](https://github.com/umbra3l/cloudguard-ci/actions/workflows/scan.yml/badge.svg)

---

## Build

```bash
g++ -std=c++17 main.cpp -o outputs/cloudguard
```

---

## Usage

```bash
# Use default tfplan.json in current directory
./outputs/cloudguard

# Pass a custom plan file
./outputs/cloudguard path/to/tfplan.json
```

### Example Output

```
[FAIL] Security Risk Found!
Resource: aws_s3_bucket.vulnerable_bucket
Issue: Bucket ACL is set to 'public-read' (it is publicly accessible to the internet!)

[FAIL] Security Risk Found!
Resource: aws_s3_bucket.public_rw_bucket
Issue: Bucket ACL is set to 'public-read-write' (it is publicly accessible to the internet!)

[FAIL] Security Risk Found!
Resource: aws_security_group.open_ssh_sg
Issue: Security Group is open.

[FAIL] Security Risk Found!
Resource: aws_security_group.open_http_sg
Issue: Security Group is open.

[FAIL] Security Risk Found!
Resource: aws_security_group.wildcard_sg
Issue: Security Group is open.
```

Exit code `1` is returned when violations are found, `0` when the plan is clean.

---

## Project Structure

```
cloudguard-ci/
├── main.cpp        # Scanner engine and all rule implementations
├── json.hpp        # nlohmann/json single-header library
├── tfplan.json     # Sample Terraform plan with safe and vulnerable resources
├── .github/
│   └── workflows/
│       └── scan.yml  # GitHub Actions CI workflow
└── outputs/
    └── cloudguard  # Compiled binary (not tracked in git)
```

---

## How It Works

The scanner is built on three core abstractions:

- **`Rule` (abstract base class)** — defines the interface every security rule must implement: `getRuleName()`, `getResourceType()`, and `evaluate()`.
- **Concrete rule classes** — each rule targets one Terraform resource type and encodes one security check in its `evaluate()` method.
- **`Scanner` (orchestrator)** — holds a list of rules, iterates over all resources in the plan, and dispatches each resource to the matching rule.

Adding a new rule requires only creating a new class that inherits from `Rule` and registering it with the scanner — no other code needs to change.

---

## Roadmap

- [x] CLI argument support for custom plan file paths
- [x] GitHub Actions CI/CD integration
- [ ] Refactor into modular `include/` and `src/` directory structure
- [ ] Add Makefile build system
- [ ] SARIF output format for GitHub Security tab integration
- [ ] Additional rules: unencrypted EBS volumes, public RDS instances, missing MFA on IAM

---

## License

MIT
