// BINARY is a deprecated alias of LATIN1.
// BASE64URL is not currently exposed to the JavaScript side.
enum encoding {
  ASCII,
  UTF8,
  BASE64,
  UCS2,
  BINARY,
  HEX,
  BUFFER,
  BASE64URL,
  LATIN1 = BINARY
};
