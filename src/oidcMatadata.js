const axios = require('axios');
const jwksClient = require('jwks-rsa');
const Token = require('./token');

class OIDCMatadata {
  constructor(url, realm, log) {
    this.log = log;
    this.url = url;
    this.discoveryUrl = `${url}/realms/${realm}/.well-known/openid-configuration`;
    this.getJwksUri().then((jwksUri) => {
      this.jwksClient = jwksClient({
        // fetcher: async (jwksUri) => {
        //   try {
        //     return await axios.get(jwksUri);
        //   } catch (error) {
        //     const errorMsg = `Cannot get AAD signing Keys from url ${jwksUri}. We got a ${error.message}`;
        //     throw new Error(errorMsg);
        //   }
        // },
        jwksUri: jwksUri
      });
      return this.jwksClient.getSigningKeys();
    }).catch((err) => {
      this.log.warn(err.message);
    });
  }

  async getJwksUri() {
    try {
      const res = await axios.get(this.discoveryUrl);
      const discoverUrls = res.data;
      if (!discoverUrls.jwks_uri) {
        throw new Error(
          `Unable to get OIDC metadata from ${this.discoveryUrl}`
        );
      }
      return discoverUrls.jwks_uri;
    } catch (error) {
      throw new Error(
        `Unable to get OIDC metadata from ${this.discoveryUrl}: ${error.message}`
      );
    }
  }

  async pemKeyFromToken(rawToken) {
    const token = new Token(rawToken);
    if (token.isExpired()) {
      this.log.info('The access token has expired');
    }
    this.log.debug(`Got token with kid: ${token.header.kid}`);

    const keyforToken = await this.jwksClient.getSigningKey(token.header.kid);
    if (!keyforToken) throw Error(`No key matching kid ${token.header.kid}`);

    return keyforToken.publicKey || keyforToken.rsaPublicKey;
  }
}

module.exports = OIDCMatadata;
