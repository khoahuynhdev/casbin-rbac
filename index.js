const { newEnforcer, newModelFromString } = require("casbin");

const model = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _
g2 = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && g2(r.obj, p.obj) && regexMatch(r.act ,p.act)
`;

// CRUD or GET/POST/PUT/DELETE
// /program, GET
// /program, POST
// /program,

// Insurance module
// /insurance/workflow CREATE
// /insurance/:id/sections READ | LIST
// /insurance/:id/preview READ
// /insurance/workflows/:workflow_id/sections/:section_id UPDATE
// /insurance/workflows/:workflow_id/sections/:section_id/assignments READ | CREATE | UPDATE
// /insurance/workflows/:workflow_id/sections/:section_id/assignments/:id DELETE
// /insurance/workflows/:workflow_id/sections/:section_id/reject CREATE
// /insurance/workflows/:workflow_id/download READ
// /insurance/coverages READ | LIST
//
//
//
//
// User awareness module
//
async function testRbacPolicies() {
  const rbacModel = newModelFromString(model);
  const enforcer = await newEnforcer(rbacModel, false);
  await enforcer.addPolicy(
    "role:operate",
    "resource",
    "(CREATE)|(UPDATE)|(DELETE)|(READ)|(LIST)"
  );
  await enforcer.addPolicy("role:view", "resource", "(READ)|(LIST)");
  await enforcer.addNamedGroupingPolicy("g2", "SECURITY", "resource");
  await enforcer.addNamedGroupingPolicy("g2", "INTEGRATION", "resource");
  await enforcer.addNamedGroupingPolicy("g2", "scan", "SECURITY");
  await enforcer.addNamedGroupingPolicy("g2", "list_scan", "SECURITY");
  await enforcer.addNamedGroupingPolicy("g2", "api_key", "SECURITY");
  await enforcer.addNamedGroupingPolicy("g2", "integration", "INTEGRATION");
  await enforcer.addNamedGroupingPolicy("g2", "jira_issue", "INTEGRATION");

  await enforcer.addGroupingPolicy("security_operator", "role:operate");
  await enforcer.addGroupingPolicy("security_viewer", "role:view");

  await enforcer.addGroupingPolicy("admin", "security_operator");
  await enforcer.addGroupingPolicy("admin", "tprm_operator");
  // we can list all modules that a role can action on
  await enforcer.addGroupingPolicy("csuite", "security_operator");
  await enforcer.addGroupingPolicy("devops", "security_operator");
  await enforcer.addGroupingPolicy("auditor", "security_viewer");

  // testing the policy
  // const res = await enforcer.enforce("security_operator", "scan", "CREATE");
  // console.log("expect true: ", res);
  //
  // const check = await enforcer.enforce("security_reader", "scan", "CREATE");
  // console.log("expect false: ", check);
  console.log(await enforcer.getImplicitRolesForUser("admin"));
  console.log(
    await enforcer.getFilteredNamedGroupingPolicy("g2", 1, "SECURITY")
  );
}

testRbacPolicies();
