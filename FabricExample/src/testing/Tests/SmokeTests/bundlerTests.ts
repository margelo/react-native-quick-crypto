import { expect } from 'chai';
import { describe, it } from '../../MochaRNAdapter';

describe('bundler smoke tests', () => {
  it('using cjs work with default import through the crypto alias', function () {
    const crypto = require('crypto');
    expect(crypto).to.be.an('object');
    const hashes = crypto.getHashes();
    expect(hashes).to.be.an('array');
  });

  it('using cjs work with the .default namespace through the crypto alias', function () {
    const crypto = require('crypto').default;
    expect(crypto).to.be.an('object');
    const hashes = crypto.getHashes();
    expect(hashes).to.be.an('array');
  });

  it('using cjs work with the install function through the crypto alias', function () {
    const install = require('crypto').install;
    expect(install).to.be.a('function');
  });

  it('using cjs work with the default import', function () {
    const crypto = require('react-native-quick-crypto');
    expect(crypto).to.be.an('object');
    const hashes = crypto.getHashes();
    expect(hashes).to.be.an('array');
  });

  it('using cjs work with the default import using the .default namespace', function () {
    const crypto = require('react-native-quick-crypto').default;
    expect(crypto).to.be.an('object');
    const hashes = crypto.getHashes();
    expect(hashes).to.be.an('array');
  });

  it('using cjs work with the install function', function () {
    const install = require('react-native-quick-crypto').install;
    expect(install).to.be.a('function');
  });

  //

  it('using esm work with an async import through the crypto alias', async function () {
    const crypto = await import('crypto');
    expect(crypto).to.be.an('object');
    const hashes = crypto.getHashes();
    expect(hashes).to.be.an('array');
  });

  it('using esm with an async import work with the install function through the crypto alias', async function () {
    // @ts-expect-error people really shouldnt be using install through the crypto alias
    const install = (await import('crypto')).install;
    expect(install).to.be.a('function');
  });

  it('using esm with an async import work with the default import', async function () {
    const crypto = (await import('react-native-quick-crypto')).default;
    expect(crypto).to.be.an('object');
    const hashes = crypto.getHashes();
    expect(hashes).to.be.an('array');
  });

  it('using esm with an async import work with the install function', async function () {
    const install = (await import('react-native-quick-crypto')).install;
    expect(install).to.be.a('function');
  });
});
