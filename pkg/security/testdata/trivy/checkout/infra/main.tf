resource "aws_security_group_rule" "ssh" {
  type        = "ingress"
  description = "ssh"
  from_port   = 22
  to_port     = 22
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

#trivy:ignore:AVD-AWS-0107
resource "aws_security_group_rule" "rdp" {
  type        = "ingress"
  description = "rdp"
  from_port   = 3389
  to_port     = 3389
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

resource "aws_security_group_rule" "db" {
  type        = "ingress"
  description = "db"
  from_port   = 5432
  to_port     = 5432
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"] #tfsec:ignore:aws-ec2-no-public-ingress-sgr
}
