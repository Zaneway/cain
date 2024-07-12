package com.github.wegoo.cain.engine.enums;

import com.github.wegoo.cain.engine.base.BaseAlgorithmEnum;

public enum KeyAlgorithmEnum implements BaseAlgorithmEnum {
  SM2("SM2",AlgorithmTypeEnum.ASYMMETRY),
  RSA("RSA",AlgorithmTypeEnum.SYMMETRY),
  SM3("SM3",AlgorithmTypeEnum.HASH)

  ;

  String algorithm;
  /**
   * asym = 非对称
   * sym = 对称
   * hash = 摘要
   *
   */
  AlgorithmTypeEnum algType;

  static final KeyAlgorithmEnum[] VALUES = values();

  KeyAlgorithmEnum(String algorithm, AlgorithmTypeEnum algType) {
    this.algorithm = algorithm;
    this.algType = algType;
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }



  @Override
  public KeyAlgorithmEnum[] getValues() {
    return VALUES;
  }
}
