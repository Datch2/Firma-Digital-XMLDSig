const fs = require('fs');
const { SignedXml } = require('xml-crypto');
const forge = require('node-forge');

console.log('Iniciando proceso de firma...');

// XML UBL 2.1 estándar limpio
const xmlBase64 = 'PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz48SW52b2ljZSB4bWxucz0idXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOnNjaGVtYTp4c2Q6SW52b2ljZS0yIiB4bWxuczpjYWM9InVybjpvYXNpczpuYW1lczpzcGVjaWZpY2F0aW9uOnVibDpzY2hlbWE6eHNkOkNvbW1vbkFnZ3JlZ2F0ZUNvbXBvbmVudHMtMiIgeG1sbnM6Y2JjPSJ1cm46b2FzaXM6bmFtZXM6c3BlY2lmaWNhdGlvbjp1Ymw6c2NoZW1hOnhzZDpDb21tb25CYXNpY0NvbXBvbmVudHMtMiIgeG1sbnM6ZHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvMDkveG1sZHNpZyMiIHhtbG5zOmV4dD0idXJuOm9hc2lzOm5hbWVzOnNwZWNpZmljYXRpb246dWJsOnNjaGVtYTp4c2Q6Q29tbW9uRXh0ZW5zaW9uQ29tcG9uZW50cy0yIj48ZXh0OlVCTEV4dGVuc2lvbnM+PGV4dDpVQkxFeHRlbnNpb24+PGV4dDpFeHRlbnNpb25Db250ZW50PjwvZXh0OkV4dGVuc2lvbkNvbnRlbnQ+PC9leHQ6VUJMRXh0ZW5zaW9uPjwvZXh0OlVCTEV4dGVuc2lvbnM+PGNiYzpVQkxWZXJzaW9uSUQ+Mi4xPC9jYmM6VUJMVmVyc2lvbklEPjxjYmM6Q3VzdG9taXphdGlvbklEPjIuMDwvY2JjOkN1c3RvbWl6YXRpb25JRD48Y2JjOklEPkYwMDEtMTwvY2JjOklEPjxjYmM6SXNzdWVEYXRlPjIwMjYtMDktMzA8L2NiYzpJc3N1ZURhdGU+PC9JbnZvaWNlPg==';
const xmlBase = Buffer.from(xmlBase64, 'base64').toString('utf8');

function extractKeysFromPfx(pfxBuffer, password) {
  const p12Asn1 = forge.asn1.fromDer(pfxBuffer.toString('binary'));
  const p12 = forge.pkcs12.pkcs12FromAsn1(p12Asn1, password);

  let key = null;
  let cert = null;

  for (const safeContent of p12.safeContents) {
    for (const safeBag of safeContent.safeBags) {
      if (safeBag.key) {
        key = forge.pki.privateKeyToPem(safeBag.key);
      }
      if (safeBag.cert) {
        cert = forge.pki.certificateToPem(safeBag.cert);
      }
    }
  }

  if (!key || !cert) {
    throw new Error('No se pudo extraer la clave o el certificado del archivo PFX.');
  }

  const cleanCert = cert
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\r?\n|\r/g, '');

  return { privateKeyPem: key, cleanCert };
}

function signSunatXml(pfxPath, pfxPassword, outputPath) {
  try {
    console.log(`Tamano del XML decodificado: ${xmlBase.length} caracteres.`);

    console.log(`Leyendo certificado desde: ${pfxPath}`);
    const pfxBuffer = fs.readFileSync(pfxPath);

    console.log('Extrayendo credenciales criptográficas...');
    const { privateKeyPem, cleanCert } = extractKeysFromPfx(pfxBuffer, pfxPassword);

    function SunatKeyInfo() {
      this.getKeyInfo = function () {
        return `${cleanCert}`;
      };
    }

    console.log('Configurando SignedXml y algoritmos SUNAT...');
    const sig = new SignedXml();
    sig.canonicalizationAlgorithm = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    sig.signatureAlgorithm = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
    sig.keyInfoProvider = new SunatKeyInfo();

    // Asignación de clave privada compatible con ambas versiones de xml-crypto
    sig.signingKey = privateKeyPem;
    sig.privateKey = privateKeyPem;

    sig.addReference({
      xpath: "/*",
      transforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature'],
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256'
    });

    console.log('Calculando firma digital XMLDSig...');
    sig.computeSignature(xmlBase, {
      signingKey: privateKeyPem,
      privateKey: privateKeyPem,
      location: {
        reference: "//*[local-name()='ExtensionContent'][1]",
        action: 'append'
      }
    });

    const signedXml = sig.getSignedXml();
    fs.writeFileSync(outputPath, signedXml, 'utf8');
    console.log(`\n Exito: Archivo firmado correctamente en ${outputPath}`);
  } catch (error) {
    console.error('\n Error durante la firma:', error.message);
  }
}

// Invocación directa
signSunatXml(
  './certificado.pfx',
  '123456',
  './factura-firmada.xml'
);