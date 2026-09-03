# Fail-before/pass-after tests: bad inputs mirror the brief's artifact (b) plus known bypass shapes; fixed inputs mirror remediate/terraform/
package main

import rego.v1

bad_db := {"resource": {"aws_db_instance": {"accounts": [{
	"identifier": "accounts-prod",
	"username": "postgres",
	"password": "${var.db_password}",
	"publicly_accessible": true,
	"storage_encrypted": false,
	"skip_final_snapshot": true,
	"backup_retention_period": 0,
}]}}}

fixed_db := {"resource": {"aws_db_instance": {"accounts": [{
	"identifier": "accounts-prod",
	"username": "accounts_admin",
	"manage_master_user_password": true,
	"publicly_accessible": false,
	"storage_encrypted": true,
	"kms_key_id": "${aws_kms_key.data.arn}",
	"backup_retention_period": 30,
	"skip_final_snapshot": false,
	"deletion_protection": true,
}]}}}

bad_sg := {"resource": {"aws_security_group_rule": {"db_ingress": [{
	"type": "ingress",
	"from_port": 5432,
	"to_port": 5432,
	"cidr_blocks": ["0.0.0.0/0"],
}]}}}

fixed_sg := {"resource": {"aws_security_group_rule": {"db_ingress": [{
	"type": "ingress",
	"from_port": 5432,
	"to_port": 5432,
	"source_security_group_id": "${var.accounts_api_pod_sg_id}",
}]}}}

bad_trail := {"resource": {"aws_cloudtrail": {"org": [{
	"name": "org-trail",
	"is_multi_region_trail": false,
	"enable_log_file_validation": false,
	"include_global_service_events": false,
}]}}}

fixed_trail := {"resource": {"aws_cloudtrail": {"org": [{
	"name": "org-trail",
	"is_multi_region_trail": true,
	"enable_log_file_validation": true,
	"include_global_service_events": true,
	"kms_key_id": "${aws_kms_key.audit.arn}",
}]}}}

all_denies := ((((((deny_rds_public | deny_rds_password_in_config) | deny_rds_unencrypted) | deny_rds_no_backups) | deny_sg_open_ingress) | deny_cloudtrail_weak) | deny_ecr_mutable_tags)

test_bad_db_public_denied if {
	count(deny_rds_public) == 1 with input as bad_db
}

test_bad_db_password_denied if {
	count(deny_rds_password_in_config) == 1 with input as bad_db
}

test_bad_db_unencrypted_denied if {
	count(deny_rds_unencrypted) == 1 with input as bad_db
}

test_bad_db_no_backups_denied if {
	count(deny_rds_no_backups) == 2 with input as bad_db
}

test_bad_sg_open_denied if {
	count(deny_sg_open_ingress) == 1 with input as bad_sg
}

test_bad_trail_denied_three_ways if {
	count(deny_cloudtrail_weak) == 3 with input as bad_trail
}

test_fixed_db_passes if {
	count(all_denies) == 0 with input as fixed_db
}

test_fixed_sg_passes if {
	count(all_denies) == 0 with input as fixed_sg
}

test_fixed_trail_passes if {
	count(all_denies) == 0 with input as fixed_trail
}

# --- bypass shapes that must ALSO be denied ---------------------------------

test_bypass_inline_ingress_denied if {
	count(deny_sg_open_ingress) == 1 with input as {"resource": {"aws_security_group": {"db": [{
		"name": "db",
		"ingress": [{"from_port": 5432, "to_port": 5432, "cidr_blocks": ["0.0.0.0/0"]}],
	}]}}}
}

test_bypass_dynamic_ingress_denied if {
	count(deny_sg_open_ingress) == 1 with input as {"resource": {"aws_security_group": {"db": [{
		"name": "db",
		"dynamic": {"ingress": [{"for_each": "${var.rules}", "content": [{"cidr_blocks": ["0.0.0.0/0"]}]}]},
	}]}}}
}

test_bypass_vpc_ingress_rule_denied if {
	count(deny_sg_open_ingress) == 2 with input as {"resource": {"aws_vpc_security_group_ingress_rule": {
		"v4": [{"security_group_id": "sg-1", "cidr_ipv4": "0.0.0.0/0", "from_port": 5432}],
		"v6": [{"security_group_id": "sg-1", "cidr_ipv6": "::/0", "from_port": 5432}],
	}}}
}

test_bypass_ipv6_blocks_denied if {
	count(deny_sg_open_ingress) == 1 with input as {"resource": {"aws_security_group_rule": {"db_ingress": [{
		"type": "ingress",
		"from_port": 5432,
		"to_port": 5432,
		"ipv6_cidr_blocks": ["::/0"],
	}]}}}
}

test_bypass_broad_halves_denied if {
	count(deny_sg_open_ingress) == 2 with input as {"resource": {"aws_security_group_rule": {"db_ingress": [{
		"type": "ingress",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["0.0.0.0/1", "128.0.0.0/1"],
	}]}}}
}

test_bypass_var_indirection_denied if {
	count(deny_rds_public) == 1 with input as {"resource": {"aws_db_instance": {"x": [{
		"publicly_accessible": "${var.make_public}",
		"storage_encrypted": true,
		"backup_retention_period": 30,
	}]}}}
}

test_bypass_aurora_denied if {
	count(all_denies) == 5 with input as {"resource": {
		"aws_rds_cluster": {"aurora": [{
			"cluster_identifier": "accounts",
			"master_password": "${var.pw}",
			"storage_encrypted": false,
			"backup_retention_period": 1,
			"skip_final_snapshot": true,
		}]},
		"aws_rds_cluster_instance": {"aurora1": [{
			"cluster_identifier": "accounts",
			"publicly_accessible": true,
		}]},
	}}
}

test_scoped_sg_prefix_passes if {
	count(deny_sg_open_ingress) == 0 with input as {"resource": {"aws_security_group_rule": {"db_ingress": [{
		"type": "ingress",
		"from_port": 5432,
		"to_port": 5432,
		"cidr_blocks": ["10.0.20.0/24"],
	}]}}}
}

test_mutable_ecr_denied if {
	count(deny_ecr_mutable_tags) == 1 with input as {"resource": {"aws_ecr_repository": {"api": [{"image_tag_mutability": "MUTABLE"}]}}}
}

test_immutable_ecr_passes if {
	count(all_denies) == 0 with input as {"resource": {"aws_ecr_repository": {"api": [{"image_tag_mutability": "IMMUTABLE", "kms_key": "${aws_kms_key.ecr.arn}"}]}}}
}

# conftest 0.56.0 stores resource bodies UNWRAPPED (bare object, no list); prove the
# rules fire identically on that shape
test_unwrapped_shape_denied if {
	count(deny_rds_public) == 1 with input as {"resource": {"aws_db_instance": {"accounts": {
		"publicly_accessible": true,
		"storage_encrypted": true,
		"backup_retention_period": 30,
	}}}}
}

test_unwrapped_ecr_immutable_passes if {
	count(deny_ecr_mutable_tags) == 0 with input as {"resource": {"aws_ecr_repository": {"api": {"image_tag_mutability": "IMMUTABLE"}}}}
}
