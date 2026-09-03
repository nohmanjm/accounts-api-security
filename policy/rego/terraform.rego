# Custom IaC rules for the section-4b defect classes; unit tests in terraform_test.rego
package main

import rego.v1

rds_resources := [[t, name, body] |
	some t in ["aws_db_instance", "aws_rds_cluster"]
	some name, bodies in object.get(input, ["resource", t], {})
	some body in bodies
]

public_capable := [[t, name, body] |
	some t in ["aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance"]
	some name, bodies in object.get(input, ["resource", t], {})
	some body in bodies
]

# fail closed: anything but a literal false (variable indirection included) is denied
deny_rds_public contains msg if {
	some entry in public_capable
	val := object.get(entry[2], "publicly_accessible", false)
	not val == false
	msg := sprintf("%s.%s: publicly_accessible must be a literal false — customer PII one password from the internet (T4)", [entry[0], entry[1]])
}

deny_rds_password_in_config contains msg if {
	some entry in rds_resources
	some key in ["password", "master_password"]
	entry[2][key]
	msg := sprintf("%s.%s: %s in config lands in state and plan output — use manage_master_user_password (T3)", [entry[0], entry[1], key])
}

deny_rds_unencrypted contains msg if {
	some entry in rds_resources
	not entry[2].storage_encrypted == true
	msg := sprintf("%s.%s: storage_encrypted must be true with a CMK (regulatory + snapshot exfil)", [entry[0], entry[1]])
}

retention_ok(r) if {
	is_number(r)
	r >= 7
}

deny_rds_no_backups contains msg if {
	some entry in rds_resources
	not retention_ok(object.get(entry[2], "backup_retention_period", 0))
	msg := sprintf("%s.%s: backup_retention_period must be a literal >= 7 — any incident becomes permanent data loss", [entry[0], entry[1]])
}

deny_rds_no_backups contains msg if {
	some entry in rds_resources
	not object.get(entry[2], "skip_final_snapshot", false) == false
	msg := sprintf("%s.%s: skip_final_snapshot must be a literal false — deletion leaves no recovery point", [entry[0], entry[1]])
}

open_cidr(cidr) if cidr == "::/0"

open_cidr(cidr) if {
	parts := split(cidr, "/")
	count(parts) == 2
	to_number(parts[1]) < 8
}

deny_sg_open_ingress contains msg if {
	some name
	some rule in input.resource.aws_security_group_rule[name]
	rule.type == "ingress"
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	open_cidr(cidr)
	msg := sprintf("aws_security_group_rule.%s: ingress open to %s — use source_security_group_id (T4)", [name, cidr])
}

deny_sg_open_ingress contains msg if {
	some name
	some sg in input.resource.aws_security_group[name]
	some ing in object.get(sg, "ingress", [])
	some cidr in array.concat(object.get(ing, "cidr_blocks", []), object.get(ing, "ipv6_cidr_blocks", []))
	open_cidr(cidr)
	msg := sprintf("aws_security_group.%s: inline ingress open to %s — use source_security_group_id (T4)", [name, cidr])
}

deny_sg_open_ingress contains msg if {
	some name
	some rule in input.resource.aws_vpc_security_group_ingress_rule[name]
	some key in ["cidr_ipv4", "cidr_ipv6"]
	open_cidr(rule[key])
	msg := sprintf("aws_vpc_security_group_ingress_rule.%s: ingress open to %s — use referenced_security_group_id (T4)", [name, rule[key]])
}

deny_sg_open_ingress contains msg if {
	some name
	some sg in input.resource.aws_security_group[name]
	object.get(sg, "dynamic", {}) != {}
	msg := sprintf("aws_security_group.%s: dynamic rule blocks are not statically analyzable — enumerate rules explicitly (T4)", [name])
}

deny_cloudtrail_weak contains msg if {
	some name
	some trail in input.resource.aws_cloudtrail[name]
	not trail.is_multi_region_trail == true
	msg := sprintf("aws_cloudtrail.%s: must be multi-region — single-region trails blind us to activity elsewhere", [name])
}

deny_cloudtrail_weak contains msg if {
	some name
	some trail in input.resource.aws_cloudtrail[name]
	not trail.enable_log_file_validation == true
	msg := sprintf("aws_cloudtrail.%s: log file validation off — trail is tamperable, hence deniable", [name])
}

deny_cloudtrail_weak contains msg if {
	some name
	some trail in input.resource.aws_cloudtrail[name]
	object.get(trail, "include_global_service_events", true) == false
	msg := sprintf("aws_cloudtrail.%s: global service (IAM/STS) events excluded — identity attacks leave no record", [name])
}

deny_ecr_mutable_tags contains msg if {
	some name
	some repo in input.resource.aws_ecr_repository[name]
	not repo.image_tag_mutability == "IMMUTABLE"
	msg := sprintf("aws_ecr_repository.%s: tags must be IMMUTABLE — mutable tags defeat signing and provenance (T1)", [name])
}

