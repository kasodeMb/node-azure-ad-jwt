const AzureActiveDirectoryValidationManager = require('./azure-ad-validation-manager.js');

module.exports.verify = async function (jwtString, options) {
    return new Promise(async (resolve, reject) => {
        try {
            const aadManager = new AzureActiveDirectoryValidationManager();

            // get the tenant id from the token
            const tenantId = aadManager.getTenantId(jwtString);

            // check if it looks like a valid AAD token
            if (!tenantId) {
                return new Error(-1, 'Not a valid AAD token');
            }

            // download the open id config
            const openIdConfig = await aadManager.requestOpenIdConfig(tenantId);

            // download the signing certificates from Microsoft for this specific tenant
            const certificates = await aadManager.requestSigningCertificates(openIdConfig.jwks_uri, options);
            console.log('certificates', certificates);
            // verify against all certificates
            const verification = aadManager.verify(jwtString, certificates, options);
            resolve(verification);
        } catch (err) {
            console.log('azure-ad-jwt ERROR', err);
            reject(err);
        }
    });
}