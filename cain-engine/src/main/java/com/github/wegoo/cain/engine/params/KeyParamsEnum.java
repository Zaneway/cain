package com.github.wegoo.cain.engine.params;

import com.github.wegoo.cain.engine.base.BaseParams;
import com.github.wegoo.cain.engine.enums.KeyAlgorithmEnum;

public enum KeyParamsEnum implements BaseParams {

  SM2(KeyAlgorithmEnum.SM2, 256),
  RSA_1024(KeyAlgorithmEnum.RSA, 1024),
  RSA_2048(KeyAlgorithmEnum.RSA, 2048),
  RSA_4096(KeyAlgorithmEnum.RSA, 4096),
  SM4_128(KeyAlgorithmEnum.SM4,128),
  AES_128(KeyAlgorithmEnum.AES,128),
  AES_192(KeyAlgorithmEnum.AES,192),
  ;

  private KeyAlgorithmEnum keyAlg;

  private int keyLen;

  KeyParamsEnum(KeyAlgorithmEnum keyAlg, int keyLen) {
    this.keyAlg = keyAlg;
    this.keyLen = keyLen;
  }

  public KeyAlgorithmEnum getKeyAlg() {
    return keyAlg;
  }

  public int getKeyLen() {
    return keyLen;
  }
}
