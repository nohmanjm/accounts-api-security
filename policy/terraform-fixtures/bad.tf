# Artifact (b) from the brief, verbatim; negative fixture that must fail conftest (see README)
resource "aws_db_instance" "accounts" {
  identifier              = "accounts-prod"
  engine                  = "postgres"
  instance_class          = "db.r6g.large"
  username                = "postgres"
  password                = var.db_password
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
}

resource "aws_security_group_rule" "db_ingress" {
  type              = "ingress"
  from_port         = 5432
  to_port           = 5432
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.db.id
}

resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = aws_s3_bucket.trail.id
  is_multi_region_trail         = false
  enable_log_file_validation    = false
  include_global_service_events = false
}

variable "db_password" { type = string }
