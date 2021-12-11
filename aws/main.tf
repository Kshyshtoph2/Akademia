terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Configure the AWS Provider
provider "aws" {
  region = "eu-central-1"
}

resource "aws_key_pair" "id_rsa" {
  key_name   = "id_rsa"
  public_key = file("${path.module}/keys/id_rsa.pub")
}

data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"]


}

resource "aws_instance" "web" {
  ami           = data.aws_ami.ubuntu.id
  instance_type = "t2.micro"
  key_name = aws_key_pair.id_rsa.key_name
  provisioner "remote-exec" {
    inline = [
      "sudo apt install nginx",
    ]
  }
    connection {
    type        = "ssh"
    host        = self.public_ip
    user        = "ubuntu"
    private_key = "${file("./keys/id_rsa.pem")}"
    timeout     = "4m"
  }
}

# resource "aws_security_group" "firewall" {
#   ingress {
#     description = "SSH"
#     from_port   = 22
#     to_port     = 22
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"] 
#   }

#   egress {
#     from_port   = 22
#     to_port     = 22  
#     protocol    = "tcp"
#     cidr_blocks = ["0.0.0.0/0"]
#   }

# }