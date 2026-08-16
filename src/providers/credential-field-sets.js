const basicCredentialFields = () => [
  {
    key: 'displayName',
    label: 'Display name',
    description: 'A unique display name for this credential.',
    type: 'text',
    required: true,
    csvAliases: ['name', 'credential_name'],
    group: 'Basic information',
    section: 'credentialDisplay',
    displayOrder: 10
  },
  {
    key: 'description',
    label: 'Description',
    description: 'Optional administrative notes for this credential.',
    type: 'textarea',
    required: false,
    csvAliases: ['notes', 'comment'],
    group: 'Basic information',
    section: 'credentialDisplay',
    displayOrder: 20
  }
];

export function oauthCredentialFields({
  defaultScopes = [],
  clientSecretRequired = true
} = {}) {
  return [
    ...basicCredentialFields(),
    {
      key: 'clientId',
      label: 'Client ID',
      description: 'OAuth application identifier issued by the provider.',
      type: 'text',
      required: true,
      group: 'Provider configuration',
      section: 'providerConfiguration',
      displayOrder: 30
    },
    {
      key: 'clientSecret',
      label: 'Client Secret',
      description: clientSecretRequired
        ? 'OAuth application secret issued by the provider.'
        : 'Optional OAuth application secret for confidential clients.',
      type: 'password',
      required: clientSecretRequired,
      secret: true,
      group: 'Provider configuration',
      section: 'providerConfiguration',
      displayOrder: 40
    },
    {
      key: 'redirectUri',
      label: 'Redirect URI',
      description: 'Callback URL registered with the provider application.',
      type: 'url',
      required: true,
      validation: { format: 'url' },
      group: 'Provider configuration',
      section: 'providerConfiguration',
      displayOrder: 50,
      visible: false,
      userConfigurable: false,
      systemManaged: true,
      readonly: true
    },
    {
      key: 'scopes',
      label: 'Scopes',
      description: 'Optional permissions requested during provider authorization.',
      type: 'oauth-scope',
      required: false,
      defaultValue: defaultScopes,
      csvAliases: ['scope', 'permissions'],
      group: 'OAuth authorization',
      section: 'scopes',
      displayOrder: 60
    },
    {
      key: 'accessToken',
      label: 'Access Token',
      description: 'OAuth access token managed by Sekalum.',
      type: 'password',
      required: false,
      secret: true,
      visible: false,
      userConfigurable: false,
      systemManaged: true,
      readonly: true,
      group: 'OAuth runtime',
      section: 'oauthRuntime',
      displayOrder: 70
    },
    {
      key: 'refreshToken',
      label: 'Refresh Token',
      description: 'OAuth refresh token managed by Sekalum.',
      type: 'password',
      required: false,
      secret: true,
      visible: false,
      userConfigurable: false,
      systemManaged: true,
      readonly: true,
      group: 'OAuth runtime',
      section: 'oauthRuntime',
      displayOrder: 80
    }
  ];
}

export function connectionCredentialFields({ defaultPort }) {
  return [
    ...basicCredentialFields(),
    {
      key: 'host',
      label: 'Host',
      description: 'Hostname or IP address of the target service.',
      type: 'text',
      required: true,
      secret: true,
      csvAliases: ['hostname', 'server'],
      group: 'Connection',
      section: 'accountCredentials',
      displayOrder: 30
    },
    {
      key: 'port',
      label: 'Port',
      description: 'Network port of the target service.',
      type: 'integer',
      required: false,
      defaultValue: defaultPort,
      validation: { minimum: 1, maximum: 65535 },
      group: 'Connection',
      section: 'accountCredentials',
      displayOrder: 40
    },
    {
      key: 'username',
      label: 'Username',
      description: 'Username used to authenticate with the target service.',
      type: 'text',
      required: true,
      secret: true,
      csvAliases: ['user'],
      group: 'Authentication',
      section: 'accountCredentials',
      displayOrder: 50
    },
    {
      key: 'password',
      label: 'Password',
      description: 'Password used to authenticate with the target service.',
      type: 'password',
      required: true,
      secret: true,
      csvAliases: ['pass'],
      group: 'Authentication',
      section: 'accountCredentials',
      displayOrder: 60
    }
  ];
}
