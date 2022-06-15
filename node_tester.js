const crypto = require('crypto');

// const key = '0123456789abcdef';
// const plaintext =
//   '32|RmVZZkFUVmpRRkp0TmJaUm56ZU9qcnJkaXNNWVNpTTU*|iXmckfRWZBGWWELw' +
//   'eCBsThSsfUHLeRe0KCsK8ooHgxie0zOINpXxfZi/oNG7uq9JWFVCk70gfzQH8ZUJ' +
//   'jAfaFg**';
// const cipher = crypto.createCipher('aes256', key);

// // Encrypt plaintext which is in utf8 format to a ciphertext which will be in
// // Base64.
// let ciph = cipher.update(plaintext, 'utf8', 'base64');
// console.warn('ciph middle', ciph);
// // Fast-crypto
// // pjH5c8XubEM+ugGSdWBaLzEbgnnMndQtcsqjVlkBkRjOq35z0OeARw9GVdNJF92TXCTisH55pT+D4XWfLi2Mj6L2aoAOCQtULNrvdMKCFOj1lyRf208lz0EzKB/P62jsJ3PR3SrNrozW6VIbcMMD40gFyw4rCaSgPwITY1w9qC0=
// // node
// // pjH5c8XubEM+ugGSdWBaLzEbgnnMndQtcsqjVlkBkRjOq35z0OeARw9GVdNJF92TXCTisH55pT+D4XWfLi2Mj6L2aoAOCQtULNrvdMKCFOj1lyRf208lz0EzKB/P62jsJ3PR3SrNrozW6VIbcMMD40gFyw4rCaSgPwITY1w9

// ciph += cipher.final('base64');
// // Fast-crypto
// // pjH5c8XubEM+ugGSdWBaLzEbgnnMndQtcsqjVlkBkRjOq35z0OeARw9GVdNJF92TXCTisH55pT+D4XWfLi2Mj6L2aoAOCQtULNrvdMKCFOj1lyRf208lz0EzKB/P62jsJ3PR3SrNrozW6VIbcMMD40gFyw4rCaSgPwITY1w9qC0=+HBnCACl/5A7vkihdZhyMw==
// // Node
// // pjH5c8XubEM+ugGSdWBaLzEbgnnMndQtcsqjVlkBkRjOq35z0OeARw9GVdNJF92TXCTisH55pT+D4XWfLi2Mj6L2aoAOCQtULNrvdMKCFOj1lyRf208lz0EzKB/P62jsJ3PR3SrNrozW6VIbcMMD40gFyw4rCaSgPwITY1w9qC34cGcIAKX/kDu+SKF1mHIz
// console.warn('ciph final', ciph);

console.warn('constants', crypto.constants);
