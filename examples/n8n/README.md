# Sekalum n8n Examples

These workflows demonstrate Sekalum's official Consumer API flow.

## Included examples

### Consumer API Example (OpenAI)

Shows:

- Discovery
- Credential Selection
- Resolve
- OpenAI Request
- Sanitized Result

### OAuth Consumer Example (Twitch)

Shows:

- Discovery
- Runtime-Public Fields
- Resolve
- OAuth Request
- Sanitized Result

### Consumer API Template

A generic starting point for custom integrations and selecting one Credential
from multiple Discovery results.

The template shows:

- one n8n item per Credential returned by Discovery;
- provider-based selection through `metadata.displayName` with a Switch;
- separate Twitch and OpenAI branches;
- forwarding the selected `credentialKey` to Resolve;
- a safe inspection branch for unconfigured providers.

Selection is independent of Discovery item order. The Sekalum node also
supports a local Provider Filter: leave it empty for all providers or enter a
provider name for variant A.

Configure only:

- Credential Display Name
- Secret Names
- Public Fields

---

## Prerequisites

- Sekalum is running
- a dedicated Consumer API token is available; never use a Management Token in a workflow
- the Credential is configured
- a matching least-privilege Consumer Grant exists for the required named fields

---

## Security boundary

Sekalum delivers Secret values only through Resolve. The OpenAI and Twitch
examples use the resolved value directly in the immediate target HTTP Request
expression. They do not copy it into an ordinary item, a Code/Set node, a URL
or query string, workflow notes, logs, execution output, retry payloads,
pinned/static data, source control, exports, screenshots or recordings.

The target request is followed by a sanitized result node. Do not add a
preparation node that returns a resolved Secret as ordinary JSON. Keep workflow
success and error retention disabled, and treat Resolve or target failures as
failures without replaying Secret-bearing data. The stable `credentialKey` is a
logical reference, not a Secret Version or Secret material; rotation may keep
the reference while replacing material, and revocation blocks future Resolve.
The generic HTTP Consumer API remains canonical; the existing native n8n node
is ordinary reference UX and Issue #173 adoption/video/workflow evidence is
separately governed. `Cache-Control: no-store` does not guarantee erasure from
the external runtime after delivery.
