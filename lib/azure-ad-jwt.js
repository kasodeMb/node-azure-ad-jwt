const exports = module.exports;

exports.AzureActiveDirectoryValidationManager = require('./azure-ad-validation-manager.js');

exports.verify = async function (jwtString, options) {

    const aadManager = new exports.AzureActiveDirectoryValidationManager();

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

    // verify against all certificates
    return aadManager.verify(jwtString, certificates, options);
}