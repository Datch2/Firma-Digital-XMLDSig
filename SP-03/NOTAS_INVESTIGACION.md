# Spike: Investigación y Firma Digital XMLDSig para SUNAT (SP-03)

## 1. Objetivo
Implementar una Prueba de Concepto (PoC) en Node.js que permita firmar digitalmente comprobantes de pago electrónicos bajo el estándar UBL 2.1 y la especificación XMLDSig exigida por SUNAT, empleando certificados digitales X.509 en formato PKCS#12 (.pfx).

## 2. Herramientas y Librerías Utilizadas
* **OpenSSL:** Utilizado para la generación del par de claves criptográficas RSA (2048 bits) y el certificado X.509 autofirmado empaquetado en formato PKCS#12 (`.pfx`).
* **`xml-crypto`:** Motor de firma digital para canonicalización (C14N) e inyección del bloque `ds:Signature`.
* **`node-forge`:** Empleado para la manipulación y extracción en memoria de la clave privada (`PEM`) y la cadena Base64 del certificado X.509 desde el archivo `.pfx`.
* **`@xmldom/xmldom`:** Parser DOM para la resolución de rutas XPath y navegación del árbol XML.

## 3. Especificación Técnica Aplicada (SUNAT UBL 2.1)
* **Punto de Inserción:** `//*[local-name()='ExtensionContent'][1]` dentro de `ext:UBLExtensions`.
* **Algoritmo de Firma:** `RSA-SHA256` (`http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`).
* **Algoritmo de Digest:** `SHA-256` (`http://www.w3.org/2001/04/xmlenc#sha256`).
* **Algoritmo de Canonicalización:** `C14N` (`http://www.w3.org/TR/2001/REC-xml-c14n-20010315`).
* **Transformación:** Enveloped Signature (`http://www.w3.org/2000/09/xmldsig#enveloped-signature`).
* **Elemento KeyInfo:** `...`.

## 4. Archivos Entregables
* `sign.js`: Script ejecutable que extrae las credenciales del `.pfx` y firma el documento XML.
* `factura-firmada.xml`: Comprobante firmado válido que contiene el nodo `` completo.
* `certificado.pfx`: Certificado digital de pruebas en formato PKCS#12.

## 5. Integración con el Flujo de Envío (SPK-02)
El XML generado queda listo para:
1. Comprimirse en archivo `.zip` con la nomenclatura `{RUC}-{TIPO}-{SERIE}-{CORRELATIVO}.zip`.
2. Codificarse en Base64.
3. Inyectarse en el tag `` del servicio SOAP `billService` de SUNAT.