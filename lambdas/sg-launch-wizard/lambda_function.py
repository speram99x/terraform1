# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Description: Check that security groups prefixed with "launch-wizard"
#              are not associated with network interfaces.'
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:NetworkInterface
# Accepted Parameters: None

import boto3
import botocore
import json
import os

APPLICABLE_RESOURCES = ["AWS::EC2::NetworkInterface"]

def evaluate_security_group(sg_groupId, included_items, excluded_items, debug_enabled):
	compliance_type = 'COMPLIANT'
	annotation = "Resource is compliant."
	# Call describe_security_groups because the IpPermissions that are returned
	# are in a format that can be used as the basis for input to
	# authorize_security_group_ingress and revoke_security_group_ingress.
	client = boto3.client("ec2");
	if (sg_groupId in excluded_items):
		print("Launch-wizard security group is in excluded group: ", sg_groupId)
		annotation = "Launch-wizard security group " + sg_groupId + " is in excluded groups"
		return {
			"compliance_type": compliance_type,
			"annotation": annotation
		}
	if (not("all" in included_items)) and (not(sg_groupId in included_items)):
		print("Launch-wizard security group is not in included items: ", sg_groupId)
		annotation = "Launch-wizard security group " + sg_groupId + " is not in included groups"
		return {
			"compliance_type": compliance_type,
			"annotation": annotation
		}

	try:
		response = client.describe_security_groups(GroupIds=[sg_groupId])
	except botocore.exceptions.ClientError as e:
		return {
			"compliance_type" : "NON_COMPLIANT",
			"annotation" : "describe_security_groups failure on group " + group_id
		}
	if debug_enabled:
		print("security group definition: ", json.dumps(response, indent=2))

	ip_permissions = response["SecurityGroups"][0]["IpPermissions"]
	ip_permissions_egress = response["SecurityGroups"][0]["IpPermissionsEgress"]

	try:
		if (len(ip_permissions) != 0):
			client.revoke_security_group_ingress(GroupId=sg_groupId, IpPermissions=ip_permissions)
		if (len(ip_permissions_egress) != 0):
			client.revoke_security_group_egress(GroupId=sg_groupId, IpPermissions=ip_permissions_egress)
	except botocore.exceptions.ClientError as e:
		return {
			"compliance_type" : "NON_COMPLIANT",
			"annotation" : "revoke_security_group_ingress failure on group " + sg_groupId
		}    
	compliance_type = 'NON_COMPLIANT'
	annotation = 'Removed IP permissions from a launch-wizard security group ' + sg['groupName'] + ' that was attached to ' + configuration_item['configuration']['privateIpAddress']
	return {
		"compliance_type": compliance_type,
		"annotation": annotation
	}


def evaluate_compliance(configuration_item, included_items, excluded_items, debug_enabled):
	# Start as compliant
	compliance_type = 'COMPLIANT'
	annotation = "Resource is compliant."

	# Check resource for applicability

	if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
		compliance_type = 'NOT_APPLICABLE'
		annotation = "The rule doesn't apply to resources of type " + configuration_item["resourceType"] + "."
	if configuration_item['configuration'] is None:
		return {
			"compliance_type": compliance_type,
			"annotation": "There are no resources to evaluate"
		}
	if configuration_item['configuration']['groups'] is None:
		if not(configuration_item['configuration']['groups'] is None):
			single_sg_id = configuration_item['configuration']['groupId']
			return evaluate_security_group(single_sg_id, included_items, excluded_items, debug_enabled)
		else:
			return {
				"compliance_type": compliance_type,
				"annotation": "There are no resources to evaluate"
			}
	
	# Iterate over security groups
	for sg in configuration_item['configuration']['groups']:
		if "launch-wizard" in sg['groupName']:
			sg_groupId = sg['groupId']
			return evaluate_security_group(sg_groupId, included_items, excluded_items, debug_enabled)
	
	return {
		"compliance_type": compliance_type,
		"annotation": annotation
	}

def lambda_handler(event, context):
	debug_enabled = True
	invoking_event = json.loads(event['invokingEvent'])
	configuration_item = invoking_event["configurationItem"]
	
	print("Invoking Event = ", invoking_event)
	print("Configuration Item = ", configuration_item)
	
	account_id = context.invoked_function_arn.split(":")[4]
	s3 = boto3.client('s3')
	
	bucket = os.environ["CENTRAL_POLICY_BUCKET"]
	# bucket = 'sp-central-policy-bucket'
	key = 'main_policy.txt'
	obj = s3.get_object(Bucket=bucket, Key=key)
	j = json.loads(obj['Body'].read())
	print("Received master policy: " + json.dumps(j, indent=2))

	included_items = ["all"]
	excluded_items = ["none"]
	account_policy_object = None
	key = "account_" + account_id + "_policy.txt"
	print("Account Key Used: " + key)
	account_policy_object = s3.get_object(Bucket=bucket, Key=key)
	if not(account_policy_object is None):
		ap = json.loads(account_policy_object['Body'].read())
		print("Received account specific policy: " + json.dumps(ap, indent=2))

	policies_enabled = False
	for item in j['policies']:
		if item['policy_name'] == 'DISALLOW_LAUNCH_WIZARD_IP_PERMISSIONS' and item['enabled'] == 'yes':
			policies_enabled = True
			if not(ap is None):
				for ap_item in ap['policies']:
					if (ap_item['policy_name'] == 'DISALLOW_LAUNCH_WIZARD_IP_PERMISSIONS') and (ap_item['enabled'] == 'yes'):
						included_items = ap_item["include"]
						excluded_items = ap_item["exclude"]
			evaluation = evaluate_compliance(configuration_item, included_items, excluded_items, debug_enabled)
    
	if policies_enabled == False:
		print('No policies were enabled')
		return

	config = boto3.client('config')

	print('Compliance evaluation for %s: %s', (configuration_item['resourceId'], evaluation["compliance_type"]))
	print('Annotation: %s', (evaluation["annotation"]))

	response = config.put_evaluations(
		Evaluations=[
			{
				'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
				'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
				'ComplianceType': evaluation["compliance_type"],
				"Annotation": evaluation["annotation"],
				'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
			},
		],
		ResultToken=event['resultToken'])