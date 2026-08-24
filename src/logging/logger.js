import { safeErrorMessage, sanitizeDiagnostic } from '../utils/safe-diagnostics.js';

export class Logger {
  info(message, context = null) {
    this.#write('INFO', message, context);
  }

  success(message, context = null) {
    this.#write('OK', message, context);
  }

  warn(message, context = null) {
    this.#write('WARN', message, context);
  }

  error(message, context = null) {
    this.#write('ERROR', message, context);
  }

  #write(level, message, context) {
    const timestamp = new Date().toISOString();
    const safeMessage = typeof message === 'string' ? safeErrorMessage(message, '') : sanitizeDiagnostic(message);
    const safeContext = context === null || context === undefined ? null : sanitizeDiagnostic(context);

    if (safeContext) {
      console.log(`[${timestamp}] [${level}] ${safeMessage}`, safeContext);
      return;
    }

    console.log(`[${timestamp}] [${level}] ${safeMessage}`);
  }
}
