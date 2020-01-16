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

APPLICABLE_RESOURCES = ["AWS::S3::Bucket"]

def evaluate_compliance(configuration_item, account_id, s3_public_access_block_enabled, debug_enabled):
	# Start as compliant
	compliance_type = 'COMPLIANT'
	annotation = "S3 public access block is compliant."

	# Check resource for applicability

	if configuration_item["resourceType"] not in APPLICABLE_RESOURCES:
		compliance_type = 'NOT_APPLICABLE'
		annotation = "The rule doesn't apply to resources of type " + configuration_item["resourceType"]

	client = boto3.client('s3control')
	
	response = ""
	try:
		response = client.get_public_access_block(
    		AccountId=account_id
		)
	except botocore.exceptions.ClientError as e:
		response = ""

	s3config = ""
	if (response != ""):
		s3config = response['PublicAccessBlockConfiguration']
	
	if debug_enabled:
		print("S3config = BEGIN", s3config, "S3config = END")
	
	try:
		if (s3config == ""):
			if (s3_public_access_block_enabled):
				response = client.put_public_access_block(
					PublicAccessBlockConfiguration={
					'BlockPublicAcls': True,
					'IgnorePublicAcls': True,
					'BlockPublicPolicy': True,
					'RestrictPublicBuckets': True
					},
					AccountId=account_id
				)
				annotation = "S3 public access block enabled for the first time."
				return {
					"compliance_type": compliance_type,
					"annotation": annotation
				}
			else:
				response = client.put_public_access_block(
					PublicAccessBlockConfiguration={
					'BlockPublicAcls': False,
					'IgnorePublicAcls': False,
					'BlockPublicPolicy': False,
					'RestrictPublicBuckets': False
					},
					AccountId=account_id
				)
				annotation = "S3 public access block disabled for the first time."
				return {
					"compliance_type": compliance_type,
					"annotation": annotation
				}
				
	except botocore.exceptions.ClientError as e:
		return {
			"compliance_type" : "NON_COMPLIANT",
			"annotation" : "call to S3 public access block failed on account " + account_id
		}
		
	try:
		if ((s3config['BlockPublicAcls'] == False) and s3_public_access_block_enabled):
			response = client.put_public_access_block(
				PublicAccessBlockConfiguration={
				'BlockPublicAcls': True,
				'IgnorePublicAcls': True,
				'BlockPublicPolicy': True,
				'RestrictPublicBuckets': True
				},
				AccountId=account_id
			)
			annotation = "S3 public access block was disabled, but now enabled."	
	except botocore.exceptions.ClientError as e:
		return {
			"compliance_type" : "NON_COMPLIANT",
			"annotation" : "call to S3 public access block failed on account " + account_id
		}

	try:
		if (s3config['BlockPublicAcls'] == True and (s3_public_access_block_enabled == False)):
			response = client.put_public_access_block(
				PublicAccessBlockConfiguration={
				'BlockPublicAcls': False,
				'IgnorePublicAcls': False,
				'BlockPublicPolicy': False,
				'RestrictPublicBuckets': False
				},
				AccountId=account_id
			)
			annotation = "S3 public access block was enabled, but now disabled."	
	except botocore.exceptions.ClientError as e:
		return {
			"compliance_type" : "NON_COMPLIANT",
			"annotation" : "call to S3 public access block failed on account " + account_id
		}

	return {
		"compliance_type": compliance_type,
		"annotation": annotation
	}

#{
#    'PublicAccessBlockConfiguration': {
#        'BlockPublicAcls': True|False,
#        'IgnorePublicAcls': True|False,
#        'BlockPublicPolicy': True|False,
#        'RestrictPublicBuckets': True|False
#    }
#}


def lambda_handler(event, context):
	debug_enabled = None
	invoking_event = json.loads(event['invokingEvent'])
	configuration_item = invoking_event["configurationItem"]
	
	if debug_enabled:
		print("Invoking Event = ", invoking_event)
		print("Configuration Item = ", configuration_item)
	
	account_id = context.invoked_function_arn.split(":")[4]
	s3 = boto3.client('s3')
	bucket = 'sp-central-policy-bucket'
	key = 'main_policy.txt'
	obj = s3.get_object(Bucket=bucket, Key=key)
	j = json.loads(obj['Body'].read())
	if debug_enabled:
		print("Received master policy: " + json.dumps(j, indent=2))

	account_policy_object = None
	key = "account_" + account_id + "_policy.txt"
	if debug_enabled:
		print("Account Key Used: " + key)
	account_policy_object = s3.get_object(Bucket=bucket, Key=key)
	if not(account_policy_object is None):
		ap = json.loads(account_policy_object['Body'].read())
		if debug_enabled:
			print("Received account specific policy: " + json.dumps(ap, indent=2))

	s3_public_access_block_enabled = True
	for item in j['policies']:
		if item['policy_name'] == 'S3_PUBLIC_ACCESS_BLOCK' and item['enabled'] == 'no':
			s3_public_access_block_enabled = False
		if not(ap is None):
			for ap_item in ap['policies']:
				if (ap_item['policy_name'] == 'S3_PUBLIC_ACCESS_BLOCK') and (ap_item['enabled'] == 'no'):
					s3_public_access_block_enabled = False
	
	evaluation = evaluate_compliance(configuration_item, account_id, s3_public_access_block_enabled, debug_enabled)

	config = boto3.client('config')

	print('Compliance evaluation for:', configuration_item['resourceId'], evaluation["compliance_type"])
	print('Annotation: ', evaluation["annotation"])

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
		ResultToken=event['resultToken']
