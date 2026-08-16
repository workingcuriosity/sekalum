<!-- GENERATED FILE. Source: ../canonical-ui-interaction-model.yaml. Do not edit manually. -->

# Canonical UI Interaction Model — Generated Tree

Status: `ACTIVE`

Generated counts: 46 nodes, 58 interactions, 22 capabilities, 7 feedback definitions.

- **Sekalum Web UI** `UI-APP` (application, ACTIVE)
  - **Admin UI** `UI-ADMIN` (area, ACTIVE)
    - **Credential Wizard** `UI-ADMIN-WIZARD` (page, ACTIVE)
      - **Open Consumer interface** `UI-CONSUMER-HANDOFF` (link, ACTIVE)
      - **Select credential type** `UI-WIZARD-STEP-TYPE` (wizard_step, ACTIVE)
      - **Select provider** `UI-WIZARD-STEP-PROVIDER` (wizard_step, ACTIVE)
      - **Enter credential data** `UI-WIZARD-STEP-FORM` (wizard_step, ACTIVE)
      - **OAuth authorization** `UI-WIZARD-STEP-OAUTH` (wizard_step, ACTIVE)
      - **Review and create credential** `UI-WIZARD-STEP-SUMMARY` (wizard_step, ACTIVE)
      - **Credential Wizard next** `UI-WIZARD-NEXT` (button, ACTIVE)
      - **Credential Wizard back** `UI-WIZARD-BACK` (button, ACTIVE)
    - **Dashboard** `UI-ADMIN-DASHBOARD` (page, ACTIVE)
    - **Custom Provider Wizard** `UI-ADMIN-PROVIDERS` (page, ACTIVE)
      - **Provider details form** `UI-PROVIDER-DETAILS` (form, ACTIVE)
      - **Provider credential methods** `UI-PROVIDER-METHODS` (panel, ACTIVE)
      - **Provider credential fields** `UI-PROVIDER-FIELDS` (panel, ACTIVE)
      - **Provider review** `UI-PROVIDER-REVIEW` (panel, ACTIVE)
    - **Credential Management** `UI-ADMIN-CREDENTIALS` (page, ACTIVE)
      - **Credentials table** `UI-CREDENTIALS-TABLE` (table, ACTIVE)
      - **Credential detail view** `UI-CREDENTIAL-DETAIL` (modal, ACTIVE)
      - **Edit credential dialog** `UI-CREDENTIAL-EDIT` (modal, ACTIVE)
      - **Delete credential confirmation** `UI-CREDENTIAL-DELETE` (confirmation, ACTIVE)
    - **Consumer Grants** `UI-ADMIN-GRANTS` (page, ACTIVE)
      - **Consumer grants table** `UI-GRANTS-TABLE` (table, ACTIVE)
      - **Edit consumer grant dialog** `UI-GRANT-EDIT` (modal, ACTIVE)
      - **Create consumer grant dialog** `UI-GRANT-CREATE` (modal, ACTIVE)
        - **Save consumer grant** `UI-GRANT-CREATE-SUBMIT` (button, ACTIVE)
      - **Consumer grants refresh** `UI-GRANT-REFRESH` (button, ACTIVE)
      - **Open consumer grant creation** `UI-GRANT-CREATE-OPEN` (button, ACTIVE)
    - **API Tokens** `UI-ADMIN-TOKENS` (page, ACTIVE)
      - **API tokens table** `UI-TOKENS-TABLE` (table, ACTIVE)
      - **Create API token dialog** `UI-TOKEN-CREATE` (modal, ACTIVE)
      - **Revoke API token confirmation** `UI-TOKEN-REVOKE` (confirmation, ACTIVE)
    - **Credential Transfer** `UI-ADMIN-TRANSFER` (page, ACTIVE)
      - **Credential export form** `UI-TRANSFER-EXPORT` (form, ACTIVE)
      - **Credential import form** `UI-TRANSFER-IMPORT` (form, ACTIVE)
    - **Admin navigation** `UI-ADMIN-NAV` (menu, ACTIVE)
    - **Admin support and legal links** `UI-ADMIN-FOOTER` (link, ACTIVE)
    - **Admin login form** `UI-ADMIN-LOGIN-FORM` (form, ACTIVE)
      - **Admin login submit** `UI-ADMIN-LOGIN-SUBMIT` (button, ACTIVE)
  - **Consumer UI** `UI-CONSUMER` (area, ACTIVE)
    - **Consumer credential discovery** `UI-CONSUMER-DISCOVERY` (panel, ACTIVE)
    - **Consumer secret resolution** `UI-CONSUMER-RESOLVE` (panel, ACTIVE)
    - **Consumer token form** `UI-CONSUMER-AUTH` (form, ACTIVE)
      - **Consumer discovery submit** `UI-CONSUMER-DISCOVERY-SUBMIT` (button, ACTIVE)
    - **Consumer status** `UI-CONSUMER-STATUS` (notification, ACTIVE)

## Route Matrix

| Route | UI node | Role | Authentication | Navigation entry | Terminal |
| --- | --- | --- | --- | --- | --- |
| `/admin/` | `UI-ADMIN-WIZARD` | administrator | management bearer token | Admin navigation → Credential Wizard | no |
| `/admin/dashboard.html` | `UI-ADMIN-DASHBOARD` | administrator | management bearer token | Admin navigation → Dashboard | no |
| `/admin/providers.html` | `UI-ADMIN-PROVIDERS` | administrator | management bearer token | Admin navigation → Providers | no |
| `/admin/credentials.html` | `UI-ADMIN-CREDENTIALS` | administrator | management bearer token | Admin navigation → Credentials | no |
| `/admin/consumer-grants.html` | `UI-ADMIN-GRANTS` | administrator | management bearer token | Admin navigation → Consumer Grants | no |
| `/admin/api-tokens.html` | `UI-ADMIN-TOKENS` | administrator | management bearer token | Admin navigation → API Tokens | no |
| `/admin/credential-transfer.html` | `UI-ADMIN-TRANSFER` | administrator | management bearer token | Admin navigation → Credential Transfer | no |
| `/consumer/` | `UI-CONSUMER` | consumer | consumer bearer token | Wizard handoff or direct route | no |

## API-only Paths

| Route | Capability | Owner | Reason |
| --- | --- | --- | --- |
| `/api/v1/management/users` | `CAP-MANAGEMENT-INTERNAL` | management boundary | no current UI surface; API-only by intentional 1.x scope |
| `/api/v1/management/roles` | `CAP-MANAGEMENT-INTERNAL` | management boundary | no current UI surface; API-only by intentional 1.x scope |
| `/api/v1/management/audit-log` | `CAP-MANAGEMENT-INTERNAL` | management boundary | no current UI surface; API-only by intentional 1.x scope |
| `/api/v1/management/metrics` | `CAP-MANAGEMENT-INTERNAL` | management boundary | no current UI surface; API-only by intentional 1.x scope |
| `/api/v1/management/backups` | `CAP-MANAGEMENT-INTERNAL` | management boundary | no current UI surface; API-only by intentional 1.x scope |

## Terminal UI Paths

| UI node | Condition | Result |
| --- | --- | --- |
| `UI-ADMIN-FOOTER` | external support, legal or security link selected | external or document destination; no in-app successor |
| `UI-CONSUMER-STATUS` | discovery or resolve completes with success or failure | terminal feedback for the current request; recovery remains available where implemented |
| `UI-WIZARD-STEP-OAUTH` | OAuth provider authorization handoff starts | external provider page; callback returns through the documented OAuth boundary |
