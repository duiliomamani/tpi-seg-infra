package support

import rego.v1

default allow := false

has_support_role if {
	"employee" in input.subject.roles
}

has_support_role if {
	"support_l1" in input.subject.roles
}

has_support_role if {
	"support_admin" in input.subject.roles
}

allow if {
	input.subject.active == true
	input.action == "kb:read"
	input.resource.approved == true
	input.resource.classification == "public"
	has_support_role
}

allow if {
	input.subject.active == true
	input.action == "kb:read"
	input.resource.approved == true
	input.resource.classification == "internal"
	input.resource.team in input.subject.assigned_queues
	"support_l1" in input.subject.roles
}

allow if {
	input.subject.active == true
	input.action == "ticket:read"
	has_support_role
	input.resource.owner_id == input.subject.sub
}

allow if {
	input.subject.active == true
	input.action == "ticket:read"
	"support_admin" in input.subject.roles
}

allow if {
	input.subject.active == true
	input.action == "groups:read"
	has_support_role
	input.resource.subject_id == input.subject.sub
}

allow if {
	input.subject.active == true
	input.action == "groups:read"
	"support_admin" in input.subject.roles
}

allow if {
	input.subject.active == true
	input.action == "ticket:read"
	"support_l1" in input.subject.roles
	input.resource.queue in input.subject.assigned_queues
}

allow if {
	input.subject.active == true
	input.action == "ticket:create"
	has_support_role
	input.resource.owner_id == input.subject.sub
	input.resource.queue == "network"
	input.resource.status == "Nuevo"
	input.resource.confirmed == true
}

allow if {
	input.subject.active == true
	input.action == "mfa:reset"
	"support_admin" in input.subject.roles
	input.resource.confirmed == true
}

allow if {
	input.subject.active == true
	input.action == "pricing:read_internal"
	"support_admin" in input.subject.roles
	input.resource.classification == "confidential"
	input.resource.department == "commercial"
}

allow if {
	input.subject.active == true
	input.action == "pricing:update"
	"support_admin" in input.subject.roles
	input.resource.classification == "confidential"
	input.resource.department == "commercial"
	input.resource.confirmed == true
	input.resource.new_price_ars >= input.resource.minimum_price_ars
}
