const PROFILE_TEMPLATES = Object.freeze([
  {
    id: 'none',
    label: 'No profile',
    classification: 'FORM_SUGGESTION_ONLY',
    description: 'Keep the existing free Consumer configuration.',
    suggestedConsumerId: '',
    recommendedScopes: ['credentials:consume'],
    suggestedSecretFields: [],
    documentationHint: 'Configure the Consumer and its existing grants manually.'
  },
  {
    id: 'n8n',
    label: 'n8n',
    classification: 'FORM_SUGGESTION_ONLY',
    description: 'Template for an n8n HTTP or node-based workflow.',
    suggestedConsumerId: 'n8n-consumer',
    recommendedScopes: ['credentials:consume'],
    suggestedSecretFields: ['apiKey', 'accessToken', 'refreshToken'],
    documentationHint: 'Use the generic Discovery → Select → Resolve flow in the n8n workflow.'
  },
  {
    id: 'make',
    label: 'Make',
    classification: 'FORM_SUGGESTION_ONLY',
    description: 'Template for a Make scenario using the Consumer API.',
    suggestedConsumerId: 'make-consumer',
    recommendedScopes: ['credentials:consume'],
    suggestedSecretFields: ['apiKey', 'accessToken', 'refreshToken'],
    documentationHint: 'Keep the Consumer token in the scenario connection and resolve only needed fields.'
  },
  {
    id: 'zapier',
    label: 'Zapier',
    classification: 'FORM_SUGGESTION_ONLY',
    description: 'Template for a Zapier action or webhook step.',
    suggestedConsumerId: 'zapier-consumer',
    recommendedScopes: ['credentials:consume'],
    suggestedSecretFields: ['apiKey', 'accessToken', 'refreshToken'],
    documentationHint: 'Use the existing HTTP Consumer API and discard resolved values after the action.'
  },
  {
    id: 'home-assistant',
    label: 'Home Assistant',
    classification: 'FORM_SUGGESTION_ONLY',
    description: 'Template for a Home Assistant integration or automation.',
    suggestedConsumerId: 'home-assistant-consumer',
    recommendedScopes: ['credentials:consume'],
    suggestedSecretFields: ['apiKey', 'accessToken', 'refreshToken'],
    documentationHint: 'Keep the integration least-privileged and request only fields required by the automation.'
  }
]);

function cloneTemplate(template) {
  return {
    ...template,
    recommendedScopes: [...template.recommendedScopes],
    suggestedSecretFields: [...template.suggestedSecretFields]
  };
}

export function listConsumerProfileTemplates() {
  return PROFILE_TEMPLATES.map(cloneTemplate);
}

export function getConsumerProfileTemplate(profileId = 'none') {
  const template = PROFILE_TEMPLATES.find((item) => item.id === profileId);
  if (!template) throw new Error('INVALID_CONSUMER_PROFILE');
  return cloneTemplate(template);
}

export function buildConsumerProfileSuggestion(profileId, credential = null) {
  const template = getConsumerProfileTemplate(profileId);
  const availableSecretFields = new Set(
    credential?.secretNames ?? credential?.secretInventory?.map((field) => field.name) ?? []
  );
  return {
    profileId: template.id,
    classification: template.classification,
    suggestedConsumerId: template.suggestedConsumerId,
    recommendedScopes: [...template.recommendedScopes],
    suggestedSecretFields: template.suggestedSecretFields.filter((name) => availableSecretFields.has(name)),
    documentationHint: template.documentationHint,
    description: template.description
  };
}

export const CONSUMER_PROFILE_IDS = Object.freeze(PROFILE_TEMPLATES.map(({ id }) => id));
