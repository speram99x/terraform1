variable "access_id" {
  type = string
}

variable "access_key" {
  type = string
}

provider "aws" {
  region     = "us-east-1"
  access_key = var.access_id
  secret_key = var.access_key
}

resource "aws_instance" "example" {
  ami           = "ami-2757f631"
  instance_type = "t2.micro"
  subnet_id = "subnet-0f4a377c755a5e8ef"
}

#data "archive_file" "lambda_zip" {
#    type          = "zip"
#    source_file   = "index.js"
#    output_path   = "lambda_function.zip"
#}

data "archive_file" "s3-public-access-block-zip2" {
  type        = "zip"
  source_file = "${path.module}/lambdas/s3-public-access-block/lambda_function.py"
  output_path = "${path.module}/lambdas/s3-public-access-block/zipfile/s3-public-access-block.zip"
}

resource "aws_lambda_function" "s3_public_access_block_lambda" {
  function_name = "sp-s3-public-access-block-lambda-2"
  role          = "arn:aws:iam::533359187263:role/service-role/SP_ServiceRoleForConfigAndS3"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.8"
#  filename      = "${path.module}/lambdas/s3-public-access-block/lambda_function.zip"
  filename     = "${path.module}/lambdas/s3-public-access-block/zipfile/s3-public-access-block.zip"
  source_code_hash = "${data.archive_file.s3-public-access-block-zip2.output_base64sha256}"
  memory_size = "256"
  timeout     = "30"
}

resource "aws_lambda_permission" "example" {
  action        = "lambda:InvokeFunction"
  function_name = "${aws_lambda_function.s3_public_access_block_lambda.function_name}"
  principal     = "config.amazonaws.com"
  statement_id  = "AllowExecutionFromConfig"
}

resource "aws_config_config_rule" "test_rule_1" {
  # ... other configuration ...
  name = "test_rule_1"

  scope {
    compliance_resource_types = [
      "AWS::S3::Bucket"
    ]
  }

  source {
    owner             = "CUSTOM_LAMBDA"
    source_identifier = "${aws_lambda_function.s3_public_access_block_lambda.arn}"
    
    source_detail {
      event_source = "aws.config" # XXX
      message_type = "ConfigurationItemChangeNotification"
    }
  }

  # depends_on = ["aws_config_configuration_recorder.example", "aws_lambda_permission.example"]
  depends_on = ["aws_lambda_permission.example", "aws_config_configuration_recorder.main_recorder"]
}

#
#
# NEW ADDITIONS
#
#

resource "aws_config_configuration_recorder_status" "foo" {
  name       = "${aws_config_configuration_recorder.main_recorder.name}"
  is_enabled = true
  depends_on = ["aws_config_delivery_channel.main_channel"]
}

resource "aws_config_delivery_channel" "main_channel" {
  name           = "default"
  s3_bucket_name = "${aws_s3_bucket.config_recorder_bucket.bucket}"
}

# S3 bucket to write the configuration changes
resource "aws_s3_bucket" "config_recorder_bucket" {
  bucket = "config-bucket-533359187263"
}

resource "aws_config_configuration_recorder" "main_recorder" {
  name     = "example"
  role_arn = "${aws_iam_role.config_recorder_role.arn}"
}

# New role for the recorder
resource "aws_iam_role" "config_recorder_role" {
  name = "sp-new-awsconfig-role"

  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "config.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

# Policy for the new role
# With privileges to write to the S3 bucket
resource "aws_iam_role_policy" "p" {
  name = "awsconfig-example"
  role = "${aws_iam_role.config_recorder_role.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:*"
      ],
      "Effect": "Allow",
      "Resource": [
        "${aws_s3_bucket.config_recorder_bucket.arn}",
        "${aws_s3_bucket.config_recorder_bucket.arn}/*"
      ]
    },
    {
        "Action": "config:Put*",
        "Effect": "Allow",
        "Resource": "*"

    }
  ]
}
POLICY
}

resource "aws_iam_role_policy_attachment" "a" {
  role       = "${aws_iam_role.config_recorder_role.name}"
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

