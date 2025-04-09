#!/usr/bin/env python3
"""
AWS Tag Usage Checker

This script checks for the usage of specified tags across various AWS services
to determine if they are being used for critical functions.
"""

import subprocess
import json
import argparse
import sys
import re
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any

class TagUsageChecker:
    def __init__(self, tags: List[str], verbose: bool = False, region: str = None):
        self.tags = tags
        self.verbose = verbose
        self.region = region
        self.region_cmd = f"--region {region}" if region else ""
        self.findings = {}
        
    def log(self, message: str):
        """Print verbose messages if verbose mode is enabled."""
        if self.verbose:
            print(f"[INFO] {message}")
            
    def run_command(self, command: str) -> Dict[str, Any]:
        """Run AWS CLI command and return JSON output."""
        self.log(f"Running: {command}")
        try:
            result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
            if not result.stdout.strip():
                return {}
            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                return {"raw_output": result.stdout}
        except subprocess.CalledProcessError as e:
            if "AccessDenied" in str(e.stderr):
                self.log(f"Access denied: {command}")
                return {}
            elif "NoSuchEntity" in str(e.stderr) or "ResourceNotFoundException" in str(e.stderr):
                return {}
            else:
                self.log(f"Error running command: {command}")
                self.log(f"Error message: {e.stderr}")
                return {}
                
    def search_json_for_tags(self, data: Dict[str, Any], tag: str) -> List[str]:
        """
        Recursively search JSON for tag references.
        Returns list of context strings where the tag was found.
        """
        matches = []
        
        def _search(obj, path=""):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    new_path = f"{path}.{k}" if path else k
                    
                    # Check if the key or value contains the tag
                    if isinstance(k, str) and tag.lower() in k.lower():
                        matches.append(f"{new_path}")
                    if isinstance(v, str) and tag.lower() in v.lower():
                        matches.append(f"{new_path} = {v}")
                        
                    _search(v, new_path)
                    
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    _search(item, f"{path}[{i}]")
        
        _search(data)
        return matches
        
    def check_ec2_instances(self, tag: str) -> List[str]:
        """Check which EC2 instances have this tag."""
        findings = []
        command = f"aws ec2 describe-instances --filters \"Name=tag-key,Values={tag}\" {self.region_cmd}"
        result = self.run_command(command)
        
        if not result or "Reservations" not in result:
            return []
            
        for reservation in result.get("Reservations", []):
            for instance in reservation.get("Instances", []):
                instance_id = instance.get("InstanceId", "Unknown")
                findings.append(f"EC2 Instance {instance_id} has tag '{tag}'")
                
        return findings
        
    def check_backup_plans(self, tag: str) -> List[str]:
        """Check if the tag is used in AWS Backup plans."""
        findings = []
        
        # Get all backup plans
        plans_command = f"aws backup list-backup-plans {self.region_cmd}"
        plans_result = self.run_command(plans_command)
        
        if not plans_result or "BackupPlansList" not in plans_result:
            return []
            
        for plan in plans_result.get("BackupPlansList", []):
            plan_id = plan.get("BackupPlanId")
            plan_name = plan.get("BackupPlanName", "Unknown")
            
            # Get plan details
            plan_details_command = f"aws backup get-backup-plan --backup-plan-id {plan_id} {self.region_cmd}"
            plan_details = self.run_command(plan_details_command)
            
            # Search in plan details
            tag_references = self.search_json_for_tags(plan_details, tag)
            if tag_references:
                for ref in tag_references:
                    findings.append(f"AWS Backup Plan '{plan_name}' references tag '{tag}' in: {ref}")
            
            # Check backup selections
            selections_command = f"aws backup list-backup-selections --backup-plan-id {plan_id} {self.region_cmd}"
            selections_result = self.run_command(selections_command)
            
            if not selections_result or "BackupSelectionsList" not in selections_result:
                continue
                
            for selection in selections_result.get("BackupSelectionsList", []):
                selection_id = selection.get("SelectionId")
                
                selection_details_command = f"aws backup get-backup-selection --backup-plan-id {plan_id} --selection-id {selection_id} {self.region_cmd}"
                selection_details = self.run_command(selection_details_command)
                
                tag_references = self.search_json_for_tags(selection_details, tag)
                if tag_references:
                    for ref in tag_references:
                        findings.append(f"AWS Backup Selection in plan '{plan_name}' references tag '{tag}' in: {ref}")
                        
        return findings
        
    def check_iam_policies(self, tag: str) -> List[str]:
        """Check if the tag is referenced in IAM policies."""
        findings = []
        
        # List policies
        policies_command = f"aws iam list-policies --scope All {self.region_cmd}"
        policies_result = self.run_command(policies_command)
        
        if not policies_result or "Policies" not in policies_result:
            return []
            
        # Only check a reasonable number of policies to avoid timeout
        policy_limit = 100
        for policy in policies_result.get("Policies", [])[:policy_limit]:
            policy_arn = policy.get("Arn")
            policy_name = policy.get("PolicyName", "Unknown")
            
            # Get default version ID
            versions_command = f"aws iam list-policy-versions --policy-arn {policy_arn} {self.region_cmd}"
            versions_result = self.run_command(versions_command)
            
            if not versions_result or "Versions" not in versions_result:
                continue
                
            for version in versions_result.get("Versions", []):
                if version.get("IsDefaultVersion"):
                    version_id = version.get("VersionId")
                    
                    # Get policy document
                    policy_command = f"aws iam get-policy-version --policy-arn {policy_arn} --version-id {version_id} {self.region_cmd}"
                    policy_details = self.run_command(policy_command)
                    
                    if not policy_details or "PolicyVersion" not in policy_details:
                        continue
                        
                    # Extract the policy document
                    policy_doc = policy_details.get("PolicyVersion", {}).get("Document", {})
                    tag_references = self.search_json_for_tags(policy_doc, tag)
                    
                    if tag_references:
                        for ref in tag_references:
                            findings.append(f"IAM Policy '{policy_name}' references tag '{tag}' in: {ref}")
                            
        return findings
        
    def check_cloudwatch_events(self, tag: str) -> List[str]:
        """Check if the tag is used in CloudWatch Events/EventBridge rules."""
        findings = []
        
        # List rules
        rules_command = f"aws events list-rules {self.region_cmd}"
        rules_result = self.run_command(rules_command)
        
        if not rules_result or "Rules" not in rules_result:
            return []
            
        for rule in rules_result.get("Rules", []):
            rule_name = rule.get("Name", "Unknown")
            
            # Get rule details
            rule_command = f"aws events describe-rule --name {rule_name} {self.region_cmd}"
            rule_details = self.run_command(rule_command)
            
            tag_references = self.search_json_for_tags(rule_details, tag)
            if tag_references:
                for ref in tag_references:
                    findings.append(f"EventBridge Rule '{rule_name}' references tag '{tag}' in: {ref}")
                    
        return findings
        
    def check_ssm_documents(self, tag: str) -> List[str]:
        """Check if the tag is used in SSM documents."""
        findings = []
        
        # List documents
        docs_command = f"aws ssm list-documents {self.region_cmd}"
        docs_result = self.run_command(docs_command)
        
        if not docs_result or "DocumentIdentifiers" not in docs_result:
            return []
            
        # Limit the number of documents to check
        doc_limit = 50
        for doc in docs_result.get("DocumentIdentifiers", [])[:doc_limit]:
            doc_name = doc.get("Name", "Unknown")
            
            # Get document details
            doc_command = f"aws ssm get-document --name {doc_name} {self.region_cmd}"
            doc_details = self.run_command(doc_command)
            
            tag_references = self.search_json_for_tags(doc_details, tag)
            if tag_references:
                for ref in tag_references:
                    findings.append(f"SSM Document '{doc_name}' references tag '{tag}' in: {ref}")
                    
        return findings
        
    def check_lambda_functions(self, tag: str) -> List[str]:
        """Check if the tag is used in Lambda functions."""
        findings = []
        
        # List functions
        functions_command = f"aws lambda list-functions {self.region_cmd}"
        functions_result = self.run_command(functions_command)
        
        if not functions_result or "Functions" not in functions_result:
            return []
            
        for function in functions_result.get("Functions", []):
            function_name = function.get("FunctionName", "Unknown")
            
            # Check function tags
            tags_command = f"aws lambda list-tags --resource {function.get('FunctionArn')} {self.region_cmd}"
            tags_result = self.run_command(tags_command)
            
            tag_references = self.search_json_for_tags(tags_result, tag)
            if tag_references:
                for ref in tag_references:
                    findings.append(f"Lambda Function '{function_name}' has tag '{tag}' in: {ref}")
                    
            # Note: We can't easily check function code for references to the tag
            # without downloading and parsing it, which would be complex
            
        return findings
        
    def check_cost_allocation_tags(self, tag: str) -> List[str]:
        """Check if the tag is used for cost allocation."""
        findings = []
        
        # List cost allocation tags
        cost_command = f"aws ce list-cost-allocation-tags {self.region_cmd}"
        cost_result = self.run_command(cost_command)
        
        tag_references = self.search_json_for_tags(cost_result, tag)
        if tag_references:
            for ref in tag_references:
                findings.append(f"Cost Allocation uses tag '{tag}' in: {ref}")
                
        return findings
        
    def check_lifecycle_policies(self, tag: str) -> List[str]:
        """Check if the tag is used in Data Lifecycle Manager policies."""
        findings = []
        
        # List DLM policies
        policies_command = f"aws dlm get-lifecycle-policies {self.region_cmd}"
        policies_result = self.run_command(policies_command)
        
        if not policies_result or "Policies" not in policies_result:
            return []
            
        for policy in policies_result.get("Policies", []):
            policy_id = policy.get("PolicyId", "Unknown")
            
            # Get policy details
            policy_command = f"aws dlm get-lifecycle-policy --policy-id {policy_id} {self.region_cmd}"
            policy_details = self.run_command(policy_command)
            
            tag_references = self.search_json_for_tags(policy_details, tag)
            if tag_references:
                for ref in tag_references:
                    findings.append(f"DLM Policy {policy_id} references tag '{tag}' in: {ref}")
                    
        return findings
        
    def check_auto_scaling_groups(self, tag: str) -> List[str]:
        """Check if the tag is used in Auto Scaling Groups."""
        findings = []
        
        # Check ASG tags
        asg_command = f"aws autoscaling describe-tags --filters \"Name=key,Values={tag}\" {self.region_cmd}"
        asg_result = self.run_command(asg_command)
        
        if not asg_result or "Tags" not in asg_result:
            return []
            
        for tag_info in asg_result.get("Tags", []):
            asg_name = tag_info.get("ResourceId", "Unknown")
            findings.append(f"Auto Scaling Group '{asg_name}' uses tag '{tag}'")
            
        return findings
        
    def check_resource_groups(self, tag: str) -> List[str]:
        """Check if the tag is used in Resource Groups."""
        findings = []
        
        # List resource groups
        groups_command = f"aws resource-groups list-groups {self.region_cmd}"
        groups_result = self.run_command(groups_command)
        
        if not groups_result or "GroupIdentifiers" not in groups_result:
            return []
            
        for group in groups_result.get("GroupIdentifiers", []):
            group_name = group.get("GroupName", "Unknown")
            
            # Get group details
            group_command = f"aws resource-groups get-group --group-name {group_name} {self.region_cmd}"
            group_details = self.run_command(group_command)
            
            tag_references = self.search_json_for_tags(group_details, tag)
            if tag_references:
                for ref in tag_references:
                    findings.append(f"Resource Group '{group_name}' references tag '{tag}' in: {ref}")
                    
        return findings
    
    def check_tag_usage(self, tag: str) -> Dict[str, List[str]]:
        """Check a single tag across all services."""
        tag_findings = {}
        
        # Define check functions for different services
        checks = {
            "EC2 Instances": self.check_ec2_instances,
            "AWS Backup": self.check_backup_plans,
            "IAM Policies": self.check_iam_policies,
            "EventBridge Rules": self.check_cloudwatch_events,
            "SSM Documents": self.check_ssm_documents,
            "Lambda Functions": self.check_lambda_functions,
            "Cost Allocation": self.check_cost_allocation_tags,
            "Lifecycle Policies": self.check_lifecycle_policies,
            "Auto Scaling Groups": self.check_auto_scaling_groups,
            "Resource Groups": self.check_resource_groups
        }
        
        # Run checks for all services
        for service, check_func in checks.items():
            self.log(f"Checking {service} for tag '{tag}'...")
            findings = check_func(tag)
            if findings:
                tag_findings[service] = findings
                
        return tag_findings

    def check_all_tags(self):
        """Check all tags across all services."""
        for tag in self.tags:
            print(f"\n[CHECKING] Tag: {tag}")
            tag_results = self.check_tag_usage(tag)
            
            if not tag_results:
                print(f"  No usages found for tag '{tag}'")
                continue
                
            for service, findings in tag_results.items():
                print(f"  [FOUND] {service}:")
                for finding in findings:
                    print(f"    - {finding}")
                    
            # Store results
            self.findings[tag] = tag_results
            
        return self.findings

def main():
    parser = argparse.ArgumentParser(description='Check AWS resources for tag usage')
    parser.add_argument('tags', nargs='+', help='Tags to check (e.g. tag1 tag2 tag3)')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--region', '-r', help='AWS region to check')
    parser.add_argument('--output', '-o', help='Save results to JSON file')
    
    args = parser.parse_args()
    
    # Print header
    print("\n===== AWS Tag Usage Checker =====")
    print(f"Searching for {len(args.tags)} tags: {', '.join(args.tags)}")
    print("This may take several minutes depending on the number of resources in your account.")
    print("==================================\n")
    
    # Check for AWS CLI
    try:
        subprocess.run(["aws", "--version"], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: AWS CLI not found or not configured. Please install and configure the AWS CLI.")
        sys.exit(1)
    
    # Check tags
    checker = TagUsageChecker(args.tags, args.verbose, args.region)
    results = checker.check_all_tags()
    
    # Print summary
    print("\n===== Results Summary =====")
    
    for tag in args.tags:
        tag_results = results.get(tag, {})
        if not tag_results:
            print(f"Tag '{tag}': No usages found")
        else:
            services = tag_results.keys()
            print(f"Tag '{tag}': Used in {len(services)} services: {', '.join(services)}")
    
    # Save results if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")
        
    print("\nDone!")

if __name__ == "__main__":
    main()
