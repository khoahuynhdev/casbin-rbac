package main

import (
	"testing"

	casbin "github.com/casbin/casbin/v2"
	model "github.com/casbin/casbin/v2/model"
)

const rbac_models = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

func TestManyRoles(t *testing.T) {
	m, _ := model.NewModelFromString(rbac_models)
	e, _ := casbin.NewEnforcer(m, false)

	roles := []string{"admin", "manager", "developer", "tester"}

	// 2500 projects
}
