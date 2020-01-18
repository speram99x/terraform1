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
  }

  # depends_on = ["aws_config_configuration_recorder.example", "aws_lambda_permission.example"]
  depends_on = ["aws_lambda_permission.example"]
}
