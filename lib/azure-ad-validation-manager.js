var jsonwebtoken = require('jsonwebtoken');
var fetch = require('node-fetch');
var cache = require('./azure-ad-cache');

function AzureActiveDirectoryValidationManager() {
    var self = this;

    function convertCertificateToBeOpenSSLCompatible(cert) {
        //Certificate must be in this specific format or else the function won't accept it
        var beginCert = "-----BEGIN CERTIFICATE-----";
        var endCert = "-----END CERTIFICATE-----";

        cert = cert.replace("\n", "");
        cert = cert.replace(beginCert, "");
        cert = cert.replace(endCert, "");

        var result = beginCert;
        while (cert.length > 0) {

            if (cert.length > 64) {
                result += "\n" + cert.substring(0, 64);
                cert = cert.substring(64, cert.length);
            }
            else {
                result += "\n" + cert;
                cert = "";
            }
        }

        if (result[result.length] != "\n")
            result += "\n";
        result += endCert + "\n";
        return result;
    }

    /*
     * Extracts the tenant id from the give jwt token
     */
    self.getTenantId = jwtString => {
        var decodedToken = jsonwebtoken.decode(jwtString);

        if (decodedToken) {
            return decodedToken.tid;
        } else {
            return null;
        }
    };

    /*
     * This function loads the open-id configuration for a specific AAD tenant
     * from a well known application.
     */
    self.requestOpenIdConfig = async (tenantId, cb) => {
        // we need to load the tenant specific open id config
        var tenantOpenIdconfig = {
            url: 'https://login.windows.net/' + tenantId + '/.well-known/openid-configuration',
        };

        var cachedValue = cache.get(tenantOpenIdconfig);
        if (cachedValue) return cachedValue;

        try {
            var result = await fetch(tenantOpenIdconfig.url, { headers: { 'Content-Type': 'application/json' } });
            console.log('requestOpenIdConfig', result);
            cache.put(tenantOpenIdconfig, result);
            return result;
        } catch (error) {
            throw error;
        }
    };

    /*
     * Download the signing certificates which is the public portion of the
     * keys used to sign the JWT token.  Signature updated to include options for the kid.
     */
    self.requestSigningCertificates = async (jwtSigningKeysLocation, options) => {

        var jwtSigningKeyRequestOptions = {
            url: jwtSigningKeysLocation,
            json: true
        };

        var cachedValue = cache.get(jwtSigningKeysLocation);
        if (cachedValue) return cachedValue;

        try {
            const result = await fetch(jwtSigningKeyRequestOptions.url, { headers: { 'Content-Type': 'application/json' } });
            console.log('requestSigningCertificates', result);
            const certificates = [];

            //Use KID to locate the public key and store the certificate chain.
            if (options && options.kid) {
                result.keys.find(function (publicKey) {
                    if (publicKey.kid === options.kid) {
                        publicKey.x5c.forEach(function (certificate) {
                            certificates.push(convertCertificateToBeOpenSSLCompatible(certificate));
                        });
                    }
                })
            } else {
                result.keys.forEach(function (publicKeys) {
                    publicKeys.x5c.forEach(function (certificate) {
                        certificates.push(convertCertificateToBeOpenSSLCompatible(certificate));
                    })
                });
            }

            // good to go
            cache.put(jwtSigningKeysLocation, certificates);
            return certificates;
        } catch (error) {
            throw error;
        }
    };

    /*
     * This function tries to verify the token with every certificate until
     * all certificates was testes or the first one matches. After that the token is valid
     */
    self.verify = (jwt, certificates, options) => {

        // ensure we have options
        if (!options) options = {};

        // set the correct algorithm
        options.algorithms = ['RS256'];

        // set the issuer we expect
        options.issuer = 'https://sts.windows.net/' + self.getTenantId(jwt) + '/';

        let valid = false;
        let lastError = null;

        certificates.every(function (certificate) {
            // verify the token
            try {
                // verify the token
                jsonwebtoken.verify(jwt, certificate, options);

                // set the state
                valid = true;
                lastError = null;

                // abort the enumeration
                return false;
            } catch (error) {

                // set teh error state
                lastError = error;

                // check if we should try the next certificate
                if (error.message === 'invalid signature') {
                    return true;
                } else {
                    return false;
                }
            }
        });

        // done
        if (valid) {
            return { token: jsonwebtoken.decode(jwt) };
        } else {
            return { error: lastError };
        }
    }
}

module.exports = exports = AzureActiveDirectoryValidationManager;
