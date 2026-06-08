# Demo 01 — Basic introspection triage

A staging GraphQL API you own returned a full introspection schema. You want a
quick attack-surface read before it ships.

The sample `introspection.json` is the result of the standard `__schema`
introspection query against a small e-commerce API. It deliberately contains
several real-world risks:

- `User.passwordHash`, `User.apiKey`, `User.legacyToken` — credential/secret fields
- `User.ssn`, `Order.creditCardNumber` — high-value PII
- `User.isAdmin` — an authorization attribute exposed as a queryable field
- Destructive / privilege-changing mutations: `deleteUser`, `resetPassword`,
  `updateUserRole`, `createUser`
- A deprecated-but-still-queryable field: `User.legacyToken`
- A recursive `User -> Order -> User` cycle (depth surface)
- No authorization directives declared in the schema

## Run it

```bash
# Human-readable table
python -m graphqlmap analyze demos/01-basic/introspection.json

# Machine-readable for pipelines (non-zero exit when findings are present)
python -m graphqlmap analyze demos/01-basic/introspection.json --format json

# Shareable self-contained HTML report (the tool's UI)
python -m graphqlmap analyze demos/01-basic/introspection.json --format html -o report.html
```

## Expected

The tool reports CRITICAL findings for the password/api-key/token fields, HIGH
for the SSN / credit-card fields and the destructive/privilege mutations,
MEDIUM for the `isAdmin` authz attribute and the missing-authz-directive signal,
and INFO for the deprecated field. Exit code is non-zero because findings exist.

This is a **defensive** assessment: it only reads an introspection document you
are authorized to analyze and never sends traffic to any endpoint.
