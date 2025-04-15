#!/usr/bin/env python3
"""
AWS Tag Collector - Script to collect all tags and their values from AWS resources:
- EC2 instances
- EBS volumes
- Lambda functions
- AWS Backup policies
- RDS snapshots
- RDS instances (added)
- EFS volumes (added)
- CloudWatch alarms

Outputs results to CSV format.
"""

import boto3
import csv
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import argparse


def get_all_regions():
    """Get all available AWS regions."""
    ec2_client = boto3.client('ec2')
    regions = [region['RegionName'] for region in ec2_client.describe_regions()['Regions']]
    return regions


def get_ec2_tags(region):
    """Get tags from all EC2 instances in a region."""
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        instances = ec2_client.describe_instances()
        
        tags_list = []
        
        for reservation in instances.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instance_id = instance['InstanceId']
                instance_tags = instance.get('Tags', [])
                
                if instance_tags:
                    for tag in instance_tags:
                        tags_list.append({
                            'ResourceId': instance_id,
                            'ResourceType': 'EC2 Instance',
                            'Region': region,
                            'TagKey': tag['Key'],
                            'TagValue': tag['Value']
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': instance_id,
                        'ResourceType': 'EC2 Instance',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
        
        return tags_list
    except Exception as e:
        print(f"Error getting EC2 tags in {region}: {e}")
        return []


def get_ebs_volume_tags(region):
    """Get tags from all EBS volumes in a region."""
    try:
        ec2_client = boto3.client('ec2', region_name=region)
        volumes = ec2_client.describe_volumes()
        
        tags_list = []
        
        for volume in volumes.get('Volumes', []):
            volume_id = volume['VolumeId']
            volume_tags = volume.get('Tags', [])
            
            if volume_tags:
                for tag in volume_tags:
                    tags_list.append({
                        'ResourceId': volume_id,
                        'ResourceType': 'EBS Volume',
                        'Region': region,
                        'TagKey': tag['Key'],
                        'TagValue': tag['Value']
                    })
            else:
                # Add "NO TAG" entry for resources without tags
                tags_list.append({
                    'ResourceId': volume_id,
                    'ResourceType': 'EBS Volume',
                    'Region': region,
                    'TagKey': 'NO TAG',
                    'TagValue': 'NO TAG'
                })
        
        return tags_list
    except Exception as e:
        print(f"Error getting EBS volume tags in {region}: {e}")
        return []


def get_lambda_tags(region):
    """Get tags from all Lambda functions in a region."""
    try:
        lambda_client = boto3.client('lambda', region_name=region)
        functions = lambda_client.list_functions()
        
        tags_list = []
        
        for function in functions.get('Functions', []):
            function_name = function['FunctionName']
            function_arn = function['FunctionArn']
            
            try:
                # Get tags for each function
                response = lambda_client.list_tags(Resource=function_arn)
                function_tags = response.get('Tags', {})
                
                if function_tags:
                    for tag_key, tag_value in function_tags.items():
                        tags_list.append({
                            'ResourceId': function_name,
                            'ResourceType': 'Lambda Function',
                            'Region': region,
                            'TagKey': tag_key,
                            'TagValue': tag_value
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': function_name,
                        'ResourceType': 'Lambda Function',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for Lambda function {function_name}: {e}")
        
        return tags_list
    except Exception as e:
        print(f"Error getting Lambda tags in {region}: {e}")
        return []


def get_backup_tags(region):
    """Get tags from all AWS Backup policies in a region."""
    try:
        backup_client = boto3.client('backup', region_name=region)
        
        tags_list = []
        
        # Get backup plans
        backup_plans = backup_client.list_backup_plans()
        
        for plan in backup_plans.get('BackupPlansList', []):
            plan_id = plan['BackupPlanId']
            plan_arn = plan['BackupPlanArn']
            
            try:
                # Get tags for each backup plan
                response = backup_client.list_tags(ResourceArn=plan_arn)
                plan_tags = response.get('Tags', {})
                
                if plan_tags:
                    for tag_key, tag_value in plan_tags.items():
                        tags_list.append({
                            'ResourceId': plan_id,
                            'ResourceType': 'Backup Plan',
                            'Region': region,
                            'TagKey': tag_key,
                            'TagValue': tag_value
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': plan_id,
                        'ResourceType': 'Backup Plan',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for Backup Plan {plan_id}: {e}")
        
        # Get backup vaults
        backup_vaults = backup_client.list_backup_vaults()
        
        for vault in backup_vaults.get('BackupVaultList', []):
            vault_name = vault['BackupVaultName']
            vault_arn = vault['BackupVaultArn']
            
            try:
                # Get tags for each backup vault
                response = backup_client.list_tags(ResourceArn=vault_arn)
                vault_tags = response.get('Tags', {})
                
                if vault_tags:
                    for tag_key, tag_value in vault_tags.items():
                        tags_list.append({
                            'ResourceId': vault_name,
                            'ResourceType': 'Backup Vault',
                            'Region': region,
                            'TagKey': tag_key,
                            'TagValue': tag_value
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': vault_name,
                        'ResourceType': 'Backup Vault',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for Backup Vault {vault_name}: {e}")
        
        return tags_list
    except Exception as e:
        print(f"Error getting Backup tags in {region}: {e}")
        return []


def get_rds_snapshot_tags(region):
    """Get tags from all RDS snapshots in a region."""
    try:
        rds_client = boto3.client('rds', region_name=region)
        
        tags_list = []
        
        # Get DB snapshots
        snapshots = rds_client.describe_db_snapshots()
        
        for snapshot in snapshots.get('DBSnapshots', []):
            snapshot_id = snapshot['DBSnapshotIdentifier']
            snapshot_arn = snapshot['DBSnapshotArn']
            
            try:
                # Get tags for each DB snapshot
                response = rds_client.list_tags_for_resource(ResourceName=snapshot_arn)
                snapshot_tags = response.get('TagList', [])
                
                if snapshot_tags:
                    for tag in snapshot_tags:
                        tags_list.append({
                            'ResourceId': snapshot_id,
                            'ResourceType': 'RDS Snapshot',
                            'Region': region,
                            'TagKey': tag['Key'],
                            'TagValue': tag['Value']
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': snapshot_id,
                        'ResourceType': 'RDS Snapshot',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for RDS Snapshot {snapshot_id}: {e}")
        
        # Get DB cluster snapshots
        cluster_snapshots = rds_client.describe_db_cluster_snapshots()
        
        for snapshot in cluster_snapshots.get('DBClusterSnapshots', []):
            snapshot_id = snapshot['DBClusterSnapshotIdentifier']
            snapshot_arn = snapshot['DBClusterSnapshotArn']
            
            try:
                # Get tags for each DB cluster snapshot
                response = rds_client.list_tags_for_resource(ResourceName=snapshot_arn)
                snapshot_tags = response.get('TagList', [])
                
                if snapshot_tags:
                    for tag in snapshot_tags:
                        tags_list.append({
                            'ResourceId': snapshot_id,
                            'ResourceType': 'RDS Cluster Snapshot',
                            'Region': region,
                            'TagKey': tag['Key'],
                            'TagValue': tag['Value']
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': snapshot_id,
                        'ResourceType': 'RDS Cluster Snapshot',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for RDS Cluster Snapshot {snapshot_id}: {e}")
        
        return tags_list
    except Exception as e:
        print(f"Error getting RDS snapshot tags in {region}: {e}")
        return []


def get_rds_instance_tags(region):
    """Get tags from all RDS instances in a region."""
    try:
        rds_client = boto3.client('rds', region_name=region)
        
        tags_list = []
        
        # Get DB instances
        instances = rds_client.describe_db_instances()
        
        for instance in instances.get('DBInstances', []):
            instance_id = instance['DBInstanceIdentifier']
            instance_arn = instance['DBInstanceArn']
            
            try:
                # Get tags for each DB instance
                response = rds_client.list_tags_for_resource(ResourceName=instance_arn)
                instance_tags = response.get('TagList', [])
                
                if instance_tags:
                    for tag in instance_tags:
                        tags_list.append({
                            'ResourceId': instance_id,
                            'ResourceType': 'RDS Instance',
                            'Region': region,
                            'TagKey': tag['Key'],
                            'TagValue': tag['Value']
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': instance_id,
                        'ResourceType': 'RDS Instance',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for RDS Instance {instance_id}: {e}")
        
        # Get DB clusters
        clusters = rds_client.describe_db_clusters()
        
        for cluster in clusters.get('DBClusters', []):
            cluster_id = cluster['DBClusterIdentifier']
            cluster_arn = cluster['DBClusterArn']
            
            try:
                # Get tags for each DB cluster
                response = rds_client.list_tags_for_resource(ResourceName=cluster_arn)
                cluster_tags = response.get('TagList', [])
                
                if cluster_tags:
                    for tag in cluster_tags:
                        tags_list.append({
                            'ResourceId': cluster_id,
                            'ResourceType': 'RDS Cluster',
                            'Region': region,
                            'TagKey': tag['Key'],
                            'TagValue': tag['Value']
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': cluster_id,
                        'ResourceType': 'RDS Cluster',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for RDS Cluster {cluster_id}: {e}")
        
        return tags_list
    except Exception as e:
        print(f"Error getting RDS instance tags in {region}: {e}")
        return []


def get_efs_tags(region):
    """Get tags from all EFS volumes in a region."""
    try:
        efs_client = boto3.client('efs', region_name=region)
        
        tags_list = []
        
        # Get EFS file systems
        file_systems = efs_client.describe_file_systems()
        
        for fs in file_systems.get('FileSystems', []):
            fs_id = fs['FileSystemId']
            
            try:
                # Get tags for each file system
                response = efs_client.list_tags_for_resource(ResourceId=fs_id)
                fs_tags = response.get('Tags', [])
                
                if fs_tags:
                    for tag in fs_tags:
                        tags_list.append({
                            'ResourceId': fs_id,
                            'ResourceType': 'EFS Volume',
                            'Region': region,
                            'TagKey': tag['Key'],
                            'TagValue': tag['Value']
                        })
                else:
                    # Add "NO TAG" entry for resources without tags
                    tags_list.append({
                        'ResourceId': fs_id,
                        'ResourceType': 'EFS Volume',
                        'Region': region,
                        'TagKey': 'NO TAG',
                        'TagValue': 'NO TAG'
                    })
            except Exception as e:
                print(f"Error getting tags for EFS Volume {fs_id}: {e}")
        
        return tags_list
    except Exception as e:
        print(f"Error getting EFS volume tags in {region}: {e}")
        return []


def get_cloudwatch_alarm_tags(region):
    """Get tags from all CloudWatch alarms in a region."""
    try:
        cloudwatch_client = boto3.client('cloudwatch', region_name=region)
        
        tags_list = []
        
        # Get all alarms
        paginator = cloudwatch_client.get_paginator('describe_alarms')
        
        for page in paginator.paginate():
            for alarm in page.get('MetricAlarms', []) + page.get('CompositeAlarms', []):
                alarm_name = alarm['AlarmName']
                alarm_arn = alarm['AlarmArn']
                
                try:
                    # Get tags for each alarm
                    response = cloudwatch_client.list_tags_for_resource(ResourceARN=alarm_arn)
                    alarm_tags = response.get('Tags', [])
                    
                    if alarm_tags:
                        for tag in alarm_tags:
                            tags_list.append({
                                'ResourceId': alarm_name,
                                'ResourceType': 'CloudWatch Alarm',
                                'Region': region,
                                'TagKey': tag['Key'],
                                'TagValue': tag['Value']
                            })
                    else:
                        # Add "NO TAG" entry for resources without tags
                        tags_list.append({
                            'ResourceId': alarm_name,
                            'ResourceType': 'CloudWatch Alarm',
                            'Region': region,
                            'TagKey': 'NO TAG',
                            'TagValue': 'NO TAG'
                        })
                except Exception as e:
                    print(f"Error getting tags for CloudWatch Alarm {alarm_name}: {e}")
        
        return tags_list
    except Exception as e:
        print(f"Error getting CloudWatch alarm tags in {region}: {e}")
        return []


def process_region(region):
    """Process a single region to get all tags."""
    print(f"Processing region: {region}")
    result = []
    result.extend(get_ec2_tags(region))
    result.extend(get_ebs_volume_tags(region))
    result.extend(get_lambda_tags(region))
    result.extend(get_backup_tags(region))
    result.extend(get_rds_snapshot_tags(region))
    result.extend(get_rds_instance_tags(region))  # Added RDS instances
    result.extend(get_efs_tags(region))  # Added EFS volumes
    result.extend(get_cloudwatch_alarm_tags(region))
    return result


def collect_all_tags(regions=None, max_workers=10):
    """Collect all tags from all regions."""
    if not regions:
        regions = get_all_regions()
        print(f"Found {len(regions)} AWS regions")
    
    all_tags = []
    
    # Use thread pool to process regions in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(process_region, regions))
    
    for result in results:
        all_tags.extend(result)
    
    return all_tags


def write_to_csv(tags_data, output_file):
    """Write tag data to CSV file."""
    if not tags_data:
        print("No tags found to write to CSV")
        return
    
    fieldnames = ['Region', 'ResourceType', 'ResourceId', 'TagKey', 'TagValue']
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(tags_data)
    
    print(f"Successfully wrote {len(tags_data)} tag entries to {output_file}")


def create_summary_csv(tags_data, output_file):
    """Create a summary CSV with unique tag keys and their values."""
    tag_summary = defaultdict(set)
    resource_type_count = defaultdict(int)
    
    for entry in tags_data:
        tag_summary[entry['TagKey']].add(entry['TagValue'])
        resource_type_count[entry['ResourceType']] += 1
    
    # Write tag key summary
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['TagKey', 'UniqueValues', 'ValuesList'])
        
        for tag_key, values in sorted(tag_summary.items()):
            writer.writerow([
                tag_key, 
                len(values), 
                ', '.join(str(value) for value in values if value)
            ])
        
        # Add a blank row for separation
        writer.writerow([])
        writer.writerow(['Resource Type Distribution'])
        writer.writerow(['ResourceType', 'Count'])
        
        for resource_type, count in sorted(resource_type_count.items()):
            writer.writerow([resource_type, count])
    
    print(f"Summary of {len(tag_summary)} unique tags written to {output_file}")
    print(f"Found tags on {len(resource_type_count)} different resource types")


def main():
    parser = argparse.ArgumentParser(description='Collect AWS resource tags')
    parser.add_argument('--regions', nargs='+', help='Specific AWS regions to scan (default: all regions)')
    parser.add_argument('--output', type=str, default='aws_tags.csv', help='Output CSV file path')
    parser.add_argument('--summary', action='store_true', help='Generate a summary of unique tags and values')
    parser.add_argument('--max-workers', type=int, default=10, help='Maximum number of worker threads')
    parser.add_argument('--resource-types', nargs='+', choices=[
        'ec2', 'ebs', 'lambda', 'backup', 'rds', 'rds-snapshot', 'efs', 'cloudwatch', 'all'
    ], default=['all'], help='Resource types to scan (default: all)')
    
    args = parser.parse_args()
    
    print("Collecting AWS resource tags...")
    tag_data = collect_all_tags(regions=args.regions, max_workers=args.max_workers)
    
    # Filter by resource type if specified
    if 'all' not in args.resource_types:
        resource_type_mapping = {
            'ec2': 'EC2 Instance',
            'ebs': 'EBS Volume',
            'lambda': 'Lambda Function',
            'backup': ['Backup Plan', 'Backup Vault'],
            'rds': ['RDS Instance', 'RDS Cluster'],
            'rds-snapshot': ['RDS Snapshot', 'RDS Cluster Snapshot'],
            'efs': 'EFS Volume',
            'cloudwatch': 'CloudWatch Alarm'
        }
        
        filtered_data = []
        for entry in tag_data:
            for resource_arg in args.resource_types:
                resource_types = resource_type_mapping.get(resource_arg, [])
                if not isinstance(resource_types, list):
                    resource_types = [resource_types]
                
                if entry['ResourceType'] in resource_types:
                    filtered_data.append(entry)
                    break
        
        tag_data = filtered_data
    
    print(f"Found {len(tag_data)} tag entries across all resources")
    
    # Write detailed results to CSV file
    write_to_csv(tag_data, args.output)
    
    if args.summary:
        summary_file = args.output.replace('.csv', '_summary.csv')
        create_summary_csv(tag_data, summary_file)


if __name__ == "__main__":
    main()
