// copied from https://github.com/crypto-browserify/pbkdf2/blob/master/test/fixtures.json
export const fixtures = {
  valid: [
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164',
        sha256:
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
        sha512:
          '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252',
        sha224:
          '3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e63155d4e490557fd85989497',
        sha384:
          'c0e14f06e49e32d73f9f52ddf1d0c5c7191609233631dadd76a567db42b78676',
        ripemd160:
          'b725258b125e0bacb0e2307e34feb16a4d0d6aed6cb4b0eee458fc1829020428',
      },
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 2,
      dkLen: 32,
      results: {
        sha1: 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957cae93136266537a8d7bf4b76',
        sha256:
          'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43',
        sha512:
          'e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c',
        sha224:
          '93200ffa96c5776d38fa10abdf8f5bfc0054b9718513df472d2331d2d1e66a3f',
        sha384:
          '54f775c6d790f21930459162fc535dbf04a939185127016a04176a0730c6f1f4',
        ripemd160:
          '768dcc27b7bfdef794a1ff9d935090fcf598555e66913180b9ce363c615e9ed9',
      },
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: 64,
      results: {
        sha1: '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164ac2e7a8e3f9d2e83ace57e0d50e5e1071367c179bc86c767fc3f78ddb561363f',
        sha256:
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b4dbf3a2f3dad3377264bb7b8e8330d4efc7451418617dabef683735361cdc18c',
        sha512:
          '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce',
        sha224:
          '3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e63155d4e490557fd859894978ab846d52a1083ac610c36c2c5ea8ce4a024dd691064d5453bd17b15ea1ac194',
        sha384:
          'c0e14f06e49e32d73f9f52ddf1d0c5c7191609233631dadd76a567db42b78676b38fc800cc53ddb642f5c74442e62be44d727702213e3bb9223c53b767fbfb5d',
        ripemd160:
          'b725258b125e0bacb0e2307e34feb16a4d0d6aed6cb4b0eee458fc18290204289e55d962783bf52237d264cbbab25f18d89d8c798f90f558ea7b45bdf3d08334',
      },
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 2,
      dkLen: 64,
      results: {
        sha1: 'ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957cae93136266537a8d7bf4b76c51094cc1ae010b19923ddc4395cd064acb023ffd1edd5ef4be8ffe61426c28e',
        sha256:
          'ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43830651afcb5c862f0b249bd031f7a67520d136470f5ec271ece91c07773253d9',
        sha512:
          'e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e',
        sha224:
          '93200ffa96c5776d38fa10abdf8f5bfc0054b9718513df472d2331d2d1e66a3f97b510224f700ce72581ffb10a1c99ec99a8cc1b951851a71f30d9265fccf912',
        sha384:
          '54f775c6d790f21930459162fc535dbf04a939185127016a04176a0730c6f1f4fb48832ad1261baadd2cedd50814b1c806ad1bbf43ebdc9d047904bf7ceafe1e',
        ripemd160:
          '768dcc27b7bfdef794a1ff9d935090fcf598555e66913180b9ce363c615e9ed953b95fd07169be535e38afbea29c030e06d14f40745b1513b7ccdf0e76229e50',
      },
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 4096,
      dkLen: 32,
      results: {
        sha1: '4b007901b765489abead49d926f721d065a429c12e463f6c4cd79401085b03db',
        sha256:
          'c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a',
        sha512:
          'd197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5',
        sha224:
          '218c453bf90635bd0a21a75d172703ff6108ef603f65bb821aedade1d6961683',
        sha384:
          '559726be38db125bc85ed7895f6e3cf574c7a01c080c3447db1e8a76764deb3c',
        ripemd160:
          '99a40d3fe4ee95869791d9faa24864562782762171480b620ca8bed3dafbbcac',
      },
    },
    {
      key: 'passwordPASSWORDpassword',
      salt: 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
      iterations: 4096,
      dkLen: 40,
      results: {
        sha1: '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038b6b89a48612c5a25284e6605e12329',
        sha256:
          '348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9',
        sha512:
          '8c0511f4c6e597c6ac6315d8f0362e225f3c501495ba23b868c005174dc4ee71115b59f9e60cd953',
        sha224:
          '056c4ba438ded91fc14e0594e6f52b87e1f3690c0dc0fbc05784ed9a754ca780e6c017e80c8de278',
        sha384:
          '819143ad66df9a552559b9e131c52ae6c5c1b0eed18f4d283b8c5c9eaeb92b392c147cc2d2869d58',
        ripemd160:
          '503b9a069633b261b2d3e4f21c5d0cafeb3f5008aec25ed21418d12630b6ce036ec82a0430ef1974',
      },
    },
    {
      key: 'pass\u00000word',
      salt: 'sa\u00000lt',
      iterations: 4096,
      dkLen: 16,
      results: {
        sha1: '345cbad979dfccb90cac5257bea6ea46',
        sha256: '1df6274d3c0bd2fc7f54fb46f149dda4',
        sha512: '336d14366099e8aac2c46c94a8f178d2',
        sha224: '0aca9ca9634db6ef4927931f633c6453',
        sha384: 'b6ab6f8f6532fd9c5c30a79e1f93dcc6',
        ripemd160: '914d58209e6483e491571a60e433124a',
      },
    },
    {
      keyHex: '63ffeeddccbbaa',
      salt: 'salt',
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: 'f6635023b135a57fb8caa89ef8ad93a29d9debb1b011e6e88bffbb212de7c01c',
        sha256:
          'dadd4a2638c1cf90a220777bc85d81859459513eb83063e3fce7d081490f259a',
        sha512:
          'f69de451247225a7b30cc47632899572bb980f500d7c606ac9b1c04f928a3488',
        sha224:
          '9cdee023b5d5e06ccd6c5467463e34fe461a7ed43977f8237f97b0bc7ebfd280',
        sha384:
          '25c72b6f0e052c883a9273a54cfd41fab86759fa3b33eb7920b923abaad62f99',
        ripemd160:
          '08609cb567308b81164fe1307c38bb9b87b072a756ce8d74760c4d216ee4e9fb',
      },
    },
    {
      description: 'Unicode salt, no truncation due to hex',
      key: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
      saltHex:
        '6d6e656d6f6e6963e383a1e383bce38388e383abe382abe38299e3838fe38299e382a6e38299e382a1e381afe3829ae381afe38299e3818fe38299e3829de38299e381a1e381a1e38299e58d81e4babae58d81e889b2',
      iterations: 2048,
      dkLen: 64,
      results: {
        sha1: '7e042a2f41ba17e2235fbc794e22a150816b0f54a1dfe113919fccb7a056066a109385e538f183c92bad896ae8b7d8e0f4cd66df359c77c8c7785cd1001c9a2c',
        sha256:
          '0b57118f2b6b079d9371c94da3a8315c3ada87a1e819b40c4c4e90b36ff2d3c8fd7555538b5119ac4d3da7844aa4259d92f9dd2188e78ac33c4b08d8e6b5964b',
        sha512:
          'ba553eedefe76e67e2602dc20184c564010859faada929a090dd2c57aacb204ceefd15404ab50ef3e8dbeae5195aeae64b0def4d2eead1cdc728a33ced520ffd',
        sha224:
          'd76474c525616ce2a527d23df8d6f6fcc4251cc3535cae4e955810a51ead1ec6acbe9c9619187ca5a3c4fd636de5b5fe58d031714731290bbc081dbf0fcb8fc1',
        sha384:
          '15010450f456769467e834db7fa93dd9d353e8bb733b63b0621090f96599ac3316908eb64ac9366094f0787cd4bfb2fea25be41dc271a19309710db6144f9b34',
        ripemd160:
          '255321c22a32f41ed925032043e01afe9cacf05470c6506621782c9d768df03c74cb3fe14a4296feba4c2825e736486fb3871e948f9c413ca006cc20b7ff6d37',
      },
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: 10,
      results: {
        sha1: '0c60c80f961f0e71f3a9',
        sha256: '120fb6cffcf8b32c43e7',
        sha512: '867f70cf1ade02cff375',
        sha224: '3c198cbdb9464b785796',
        sha384: 'c0e14f06e49e32d73f9f',
        ripemd160: 'b725258b125e0bacb0e2',
      },
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: 100,
      results: {
        sha1: '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164ac2e7a8e3f9d2e83ace57e0d50e5e1071367c179bc86c767fc3f78ddb561363fc692ba406d1301e42bcccc3c520d06751d78b80c3db926b16ffa3395bd697c647f280b51',
        sha256:
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b4dbf3a2f3dad3377264bb7b8e8330d4efc7451418617dabef683735361cdc18c22cd7fe60fa40e91c65849e1f60c0d8b62a7b2dbd0d3dfd75fb8498a5c2131ab02b66de5',
        sha512:
          '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce7b532e206c2967d4c7d2ffa460539fc4d4e5eec70125d74c6c7cf86d25284f297907fcea',
        sha224:
          '3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e63155d4e490557fd859894978ab846d52a1083ac610c36c2c5ea8ce4a024dd691064d5453bd17b15ea1ac1944bbfd62e61b997e7b22660f588e297186572480015f33bc2bfd2b423827bcdcdb4845914',
        sha384:
          'c0e14f06e49e32d73f9f52ddf1d0c5c7191609233631dadd76a567db42b78676b38fc800cc53ddb642f5c74442e62be44d727702213e3bb9223c53b767fbfb5db9d270d54c45d9cb6003d2967280b22671e2dbc6375f6ebf219c36f0d127be35e19d65a8',
        ripemd160:
          'b725258b125e0bacb0e2307e34feb16a4d0d6aed6cb4b0eee458fc18290204289e55d962783bf52237d264cbbab25f18d89d8c798f90f558ea7b45bdf3d083340c18b9d23ba842183c5364d18bc0ffde5a8a408dd7ef02dde561a08d21c6d2325a69869b',
      },
    },
    {
      keyUint8Array: [112, 97, 115, 115, 119, 111, 114, 100],
      salt: 'salt',
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164',
        sha256:
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
        sha512:
          '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252',
        sha224:
          '3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e63155d4e490557fd85989497',
        sha384:
          'c0e14f06e49e32d73f9f52ddf1d0c5c7191609233631dadd76a567db42b78676',
        ripemd160:
          'b725258b125e0bacb0e2307e34feb16a4d0d6aed6cb4b0eee458fc1829020428',
      },
    },
    {
      key: 'password',
      saltUint8Array: [115, 97, 108, 116],
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: '0c60c80f961f0e71f3a9b524af6012062fe037a6e0f0eb94fe8fc46bdc637164',
        sha256:
          '120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b',
        sha512:
          '867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252',
        sha224:
          '3c198cbdb9464b7857966bd05b7bc92bc1cc4e6e63155d4e490557fd85989497',
        sha384:
          'c0e14f06e49e32d73f9f52ddf1d0c5c7191609233631dadd76a567db42b78676',
        ripemd160:
          'b725258b125e0bacb0e2307e34feb16a4d0d6aed6cb4b0eee458fc1829020428',
      },
    },
    {
      keyInt32Array: [112, 97, 115, 115, 119, 111, 114, 100],
      salt: 'salt',
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: 'f260ccd0bbc8fe6773119b834feec48636b716caad4180a4d0af4f9aa67c646e',
        sha256:
          '9b4608f5eeab348f0b9d85a918b140706b24f275acf6829382dfee491015f9eb',
        sha512:
          'c44b8f26550fe6ca0a55bce54b4a75e9530398f32ec28b59d0fded996e95e3d5',
        sha224:
          '03d0c2b530ec6339e6418cb0f906e50591619be40aa8817aa9c7305d1773231c',
        sha384:
          '2e69d62ae8c21ebc2de45a885b488f65fb88dfa58aaa9c57dd1fcb9d1edce96a',
        ripemd160:
          'fc69276ba3f145492065feb0259b9edf68179f2023c95094e71ac7d01748018a',
      },
    },
    {
      key: 'password',
      saltInt32Array: [115, 97, 108, 116],
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: 'b297f1ea23008f10ba9d645961e4661109e804b10af26bea22c44244492d6252',
        sha256:
          'f678f0772894c079f21377d9ee1e76dd77b62dfc1f0575e6aa9eb030af7a356a',
        sha512:
          '7f8133f6937ae1d7e4a43c19aabd2de8308d5b833341281716a501334cdb2470',
        sha224:
          'ab66d29d3dacc731e44f091a7baa051926219cf493e8b9e3934cedfb215adc8b',
        sha384:
          'cf139d648cf63e9b85a3b9b8f23f4445b84d22201bc2544bc273a17d5dcb7b28',
        ripemd160:
          '26142e48fae1ad1c53be54823aadda2aa7d42f5524463fb1eff0efafa08edb9d',
      },
    },
    {
      keyFloat64Array: [112, 97, 115, 115, 119, 111, 114, 100],
      salt: 'salt',
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: 'c2b17a7e98cc48690a92cd9f753a2c700229045905167571aa281aafe8230bba',
        sha256:
          '55d62579a083a6c14b886710f81b54f567d214d343af776e5e90c467ea81b821',
        sha512:
          'ded01ce343e2683d962fc74b7b5ceef525228f49393ce9353254f44e3dc7e9aa',
        sha224:
          '5f10a348d320c7555b972b8d7d45a363a91e1a82dea063c3ac495cfad74a8d89',
        sha384:
          '4b7f97dbadfd652e0579499d0e23607ec476ed4bea9d6f1740d0b110e2d08792',
        ripemd160:
          'f92080d972a649d98d91a53922863fc7b8076c54869e9885f9a804868ef752e0',
      },
    },
    {
      key: 'password',
      saltFloat64Array: [115, 97, 108, 116],
      iterations: 1,
      dkLen: 32,
      results: {
        sha1: 'f158b9edd28c16ad3b41e0e8197ec132a98c2ddea73b959f55ec9792e0b29d6f',
        sha256:
          'a6154d17480547a10212f75883509842f88f2ca5d6c1a2419646e47342051852',
        sha512:
          'b10c2ea742de7dd0525988761ee1733564c91380eeaa1b199f4fafcbf7144b0c',
        sha224:
          '29b315ac30c7d5e1640ca0f9e27b68a794fb9f950b8dd117129824f103ffb9db',
        sha384:
          '624b4ed6ad389b976fb7503e54a35109f249c29ac6eb8b56850152be21b3cb0e',
        ripemd160:
          '8999b9280207bc9c76cf25327aa352da26a683fac7a2adff17a39dcc4f4c3b5b',
      },
    },
  ],
  invalid: [
    {
      key: 'password',
      salt: 'salt',
      iterations: 'NaN',
      dkLen: 16,
      exception: 'Iterations not a number',
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: -1,
      dkLen: 16,
      exception: 'Bad iterations',
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: 'NaN',
      exception: 'Key length not a number',
    },
    {
      key: 'password',
      salt: 'salt',
      iterations: 1,
      dkLen: -1,
      exception: 'Bad key length',
    },
  ],
};
