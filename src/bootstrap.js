// Copyright (C) 2026 Working Curiosity
//
// This file is part of Credential HUB.
//
// Credential HUB is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License version 3
// as published by the Free Software Foundation.
//
// See the LICENSE file for details.

import 'dotenv/config';

import { Container } from './container/container.js';
import { TOKENS } from './container/tokens.js';
import { ApplicationServiceProvider } from './container/application-service-provider.js';

import { ThreadsServiceProvider } from './providers/threads/threads-service-provider.js';
import { GoogleServiceProvider } from './providers/google/google-service-provider.js';
import { TwitchServiceProvider } from './providers/twitch/twitch-service-provider.js';
import { KickServiceProvider } from './providers/kick/kick-service-provider.js';
import { DiscordServiceProvider } from './providers/discord/discord-service-provider.js';
import { XServiceProvider } from './providers/x/x-service-provider.js';
import { FacebookServiceProvider } from './providers/facebook/facebook-service-provider.js';
import { InstagramServiceProvider } from './providers/instagram/instagram-service-provider.js';
import { SftpServiceProvider } from './providers/sftp/sftp-service-provider.js';
import { FtpServiceProvider } from './providers/ftp/ftp-service-provider.js';
import { OpenAIServiceProvider } from './providers/openai/openai-service-provider.js';
import { CustomProviderServiceProvider } from './providers/custom/custom-provider-service-provider.js';

export async function bootstrap() {
  const container = new Container();

  new ApplicationServiceProvider().register(container);
  new ThreadsServiceProvider().register(container);
  new GoogleServiceProvider().register(container);
  new TwitchServiceProvider().register(container);
  new KickServiceProvider().register(container);
  new DiscordServiceProvider().register(container);
  new XServiceProvider().register(container);
  new FacebookServiceProvider().register(container);
  new InstagramServiceProvider().register(container);
  new SftpServiceProvider().register(container);
  new FtpServiceProvider().register(container);
  new OpenAIServiceProvider().register(container);
  new CustomProviderServiceProvider().register(container);
  await container.resolve(TOKENS.CUSTOM_PROVIDER_SERVICE).hydrate();

  const logger = container.resolve(TOKENS.LOGGER);

  logger.info('Application container built');

  return container.resolve(TOKENS.APPLICATION);
}
