# Custom IaC rules for the section-4b defect classes; unit tests in terraform_test.rego
package main

import rego.v1

# conftest's hcl2 parser wraps resource bodies in a list on some versions and stores
# a bare object on others; normalise both so the rules read the same everywhere
as_list(v) := v if is_array(v)

as_list(v) := [v] if is_object(v)

instances(type) := [[type, name, body] |
	some name, val in object.get(input.resource, type, {})
	some body in as_list(val)
]

rds_resources := array.concat(instances("aws_db_instance"), instances("aws_rds_cluster"))

public_capable := array.concat(rds_resources, instances("aws_rds_cluster_instance"))

deny_rds_public contains msg if {
	some [type, name, body] in public_capable
	not object.get(body, "publicly_accessible", false) == false
	msg := sprintf("%s.%s: publicly_accessible must be a literal false — customer PII one password from the internet (T4)", [type, name])
}

deny_rds_password_in_config contains msg if {
	some [type, name, body] in rds_resources
	some key in ["password", "master_password"]
	body[key]
	msg := sprintf("%s.%s: %s in config lands in state and plan output — use manage_master_user_password (T3)", [type, name, key])
}

deny_rds_unencrypted contains msg if {
	some [type, name, body] in rds_resources
	not body.storage_encrypted == true
	msg := sprintf("%s.%s: storage_encrypted must be true with a CMK (regulatory + snapshot exfil)", [type, name])
}

retention_ok(r) if {
	is_number(r)
	r >= 7
}

deny_rds_no_backups contains msg if {
	some [type, name, body] in rds_resources
	not retention_ok(object.get(body, "backup_retention_period", 0))
	msg := sprintf("%s.%s: backup_retention_period must be a literal >= 7 — any incident becomes permanent data loss", [type, name])
}

deny_rds_no_backups contains msg if {
	some [type, name, body] in rds_resources
	not object.get(body, "skip_final_snapshot", false) == false
	msg := sprintf("%s.%s: skip_final_snapshot must be a literal false — deletion leaves no recovery point", [type, name])
}

open_cidr(cidr) if cidr == "::/0"

open_cidr(cidr) if {
	parts := split(cidr, "/")
	count(parts) == 2
	to_number(parts[1]) < 8
}

deny_sg_open_ingress contains msg if {
	some [_, name, body] in instances("aws_security_group_rule")
	body.type == "ingress"
	some cidr in array.concat(object.get(body, "cidr_blocks", []), object.get(body, "ipv6_cidr_blocks", []))
	open_cidr(cidr)
	msg := sprintf("aws_security_group_rule.%s: ingress open to %s — use source_security_group_id (T4)", [name, cidr])
}

deny_sg_open_ingress contains msg if {
	some [_, name, body] in instances("aws_security_group")
	some ing in as_list(object.get(body, "ingress", []))
	some cidr in array.concat(object.get(ing, "cidr_blocks", []), object.get(ing, "ipv6_cidr_blocks", []))
	open_cidr(cidr)
	msg := sprintf("aws_security_group.%s: inline ingress open to %s — use source_security_group_id (T4)", [name, cidr])
}

deny_sg_open_ingress contains msg if {
	some [_, name, body] in instances("aws_vpc_security_group_ingress_rule")
	some key in ["cidr_ipv4", "cidr_ipv6"]
	open_cidr(body[key])
	msg := sprintf("aws_vpc_security_group_ingress_rule.%s: ingress open to %s — use referenced_security_group_id (T4)", [name, body[key]])
}

deny_sg_open_ingress contains msg if {
	some [_, name, body] in instances("aws_security_group")
	object.get(body, "dynamic", {}) != {}
	msg := sprintf("aws_security_group.%s: dynamic rule blocks are not statically analyzable — enumerate rules explicitly (T4)", [name])
}

deny_cloudtrail_weak contains msg if {
	some [_, name, body] in instances("aws_cloudtrail")
	not body.is_multi_region_trail == true
	msg := sprintf("aws_cloudtrail.%s: must be multi-region — single-region trails blind us to activity elsewhere", [name])
}

deny_cloudtrail_weak contains msg if {
	some [_, name, body] in instances("aws_cloudtrail")
	not body.enable_log_file_validation == true
	msg := sprintf("aws_cloudtrail.%s: log file validation off — trail is tamperable, hence deniable", [name])
}

deny_cloudtrail_weak contains msg if {
	some [_, name, body] in instances("aws_cloudtrail")
	object.get(body, "include_global_service_events", true) == false
	msg := sprintf("aws_cloudtrail.%s: global service (IAM/STS) events excluded — identity attacks leave no record", [name])
}

deny_ecr_mutable_tags contains msg if {
	some [_, name, body] in instances("aws_ecr_repository")
	not body.image_tag_mutability == "IMMUTABLE"
	msg := sprintf("aws_ecr_repository.%s: tags must be IMMUTABLE — mutable tags defeat signing and provenance (T1)", [name])
}
