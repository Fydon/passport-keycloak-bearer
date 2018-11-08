import simpleLogger from 'simple-node-logger';

export const verifyOptions = (options) => {
  if (!options || typeof options !== 'object') {
    throw new TypeError('KeycloakBearerStrategy: options is required');
  }
  if (!options.realm) {
    throw new TypeError('KeycloakBearerStrategy: realm cannot be empty');
  }
  if (!options.host || options.host === '') {
    throw new TypeError('KeycloakBearerStrategy: host cannot be empty');
  }
  if (options.customLogger) {
    if (typeof options.customLogger.error !== 'function') {
      throw new TypeError(
        'KeycloakBearerStrategy: customLogger must have a error function',
      );
    }
    if (typeof options.customLogger.warn !== 'function') {
      throw new TypeError(
        'KeycloakBearerStrategy: customLogger must have a warn function',
      );
    }
    if (typeof options.customLogger.info !== 'function') {
      throw new TypeError(
        'KeycloakBearerStrategy: customLogger must have a info function',
      );
    }
    if (typeof options.customLogger.debug !== 'function') {
      throw new TypeError(
        'KeycloakBearerStrategy: customLogger must have a debug function',
      );
    }
  }
};

export const setDefaults = (options) => {
  const opt = {
    ...options,
    name: options.name || 'keycloak',
    loggingLevel: options.loggingLevel || 'warn',
  };

  if (options.customLogger) {
    opt.log = options.customLogger;
  } else {
    opt.log = simpleLogger.createSimpleLogger();
    opt.log.setLevel(opt.loggingLevel);
  }

  return opt;
};
