# Security Policy (Internal Use)

## Authorized Use Only

This repository is intended for internal security consulting teams conducting **authorized Azure Cloud Configuration Reviews**. Unauthorized use is prohibited.

## Sensitive Data Handling

- Do **not** commit credentials, secrets, tokens, or service principal material.
- Do **not** commit assessment output (JSON/CSV/log/report artifacts) containing customer environment data.
- Store engagement output only in approved internal evidence repositories per company policy.

## Least Privilege Guidance

Use least-privilege service principals scoped only to approved in-scope subscriptions/tenant resources:
- Reader
- Security Reader
- Global Reader (Entra ID)
- Required Graph permissions only

## Reporting Security Issues

Report repository security concerns internally through your organization’s designated security escalation channel (for example, internal ticketing queue or security engineering contact), and include:
- Affected file(s)
- Reproduction details
- Potential impact
- Suggested remediation
