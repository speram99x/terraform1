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
  filename      = "${archive_file.s3-public-access-block-zip2.output_path"
  memory_size = "256"
  timeout     = "30"
}
