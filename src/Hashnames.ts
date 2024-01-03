export enum HashContext {
  Node,
  WebCrypto,
  JwkRsa,
  JwkRsaPss,
  JwkRsaOaep,
  JwkHmac,
};

// WebCrypto and JWK use a bunch of different names for the
// standard set of SHA-* digest algorithms... which is ... fun.
// Here we provide a utility for mapping between them in order
// make it easier in the code.

type HashNames = {
  [key: string]: { [key in HashContext as string]: string; };
};

const kHashNames: HashNames = {
  sha1: {
    [HashContext.Node]: 'sha1',
    [HashContext.WebCrypto]: 'SHA-1',
    [HashContext.JwkRsa]: 'RS1',
    [HashContext.JwkRsaPss]: 'PS1',
    [HashContext.JwkRsaOaep]: 'RSA-OAEP',
    [HashContext.JwkHmac]: 'HS1',
  },
  sha256: {
    [HashContext.Node]: 'sha256',
    [HashContext.WebCrypto]: 'SHA-256',
    [HashContext.JwkRsa]: 'RS256',
    [HashContext.JwkRsaPss]: 'PS256',
    [HashContext.JwkRsaOaep]: 'RSA-OAEP-256',
    [HashContext.JwkHmac]: 'HS256',
  },
  sha384: {
    [HashContext.Node]: 'sha384',
    [HashContext.WebCrypto]: 'SHA-384',
    [HashContext.JwkRsa]: 'RS384',
    [HashContext.JwkRsaPss]: 'PS384',
    [HashContext.JwkRsaOaep]: 'RSA-OAEP-384',
    [HashContext.JwkHmac]: 'HS384',
  },
  sha512: {
    [HashContext.Node]: 'sha512',
    [HashContext.WebCrypto]: 'SHA-512',
    [HashContext.JwkRsa]: 'RS512',
    [HashContext.JwkRsaPss]: 'PS512',
    [HashContext.JwkRsaOaep]: 'RSA-OAEP-512',
    [HashContext.JwkHmac]: 'HS512',
  },
};

{
  // Index the aliases
  const keys: string[] = Object.keys(kHashNames);
  for (let n: number = 0; n < keys.length; n++) {
    const contexts: string[] = Object.keys(kHashNames[keys[n]!]!);
    for (let i: number = 0; i < contexts.length; i++) {
      const alias: string =
        (kHashNames[keys[n]!]![contexts[i]!]!).toLowerCase();
      if (kHashNames[alias] === undefined)
        kHashNames[alias] = kHashNames[keys[n]!]!;
    }
  }
}

export function normalizeHashName(name: string, context: HashContext = HashContext.Node) {
  if (typeof name !== 'string')
    return name;
  name = name.toLowerCase();
  try {
    const alias = kHashNames[name]![context];
    return alias || name;
  } catch(_e) {}
  return name;
}
