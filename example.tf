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
