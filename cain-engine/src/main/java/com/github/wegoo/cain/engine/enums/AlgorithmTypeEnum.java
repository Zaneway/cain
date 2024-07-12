package com.github.wegoo.cain.engine.enums;

import com.github.wegoo.cain.engine.base.BaseEnum;

public enum AlgorithmTypeEnum implements BaseEnum {
  ASYMMETRY,//非对称
  SYMMETRY,//对称
  HASH,//摘要
  MAC

  ;
  static final AlgorithmTypeEnum[] VALUES = values();

  @Override
  public AlgorithmTypeEnum[] getValues() {
    return VALUES;
  }
}
