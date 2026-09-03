# DEMONSTRATION ONLY. Intentionally insecure resource used to show the IaC gate
# blocking a pull request; never merged to main. Reintroduces the Section-4b T4
# defect (internet-reachable, unencrypted, unrecoverable database).
resource "aws_db_instance" "insecure_demo" {
  identifier              = "demo"
  engine                  = "postgres"
  instance_class          = "db.t3.micro"
  allocated_storage       = 20
  username                = "postgres"
  password                = var.demo_password
  publicly_accessible     = true
  storage_encrypted       = false
  skip_final_snapshot     = true
  backup_retention_period = 0
}

variable "demo_password" { type = string }
