package com.github.wegoo.cain.engine.base;

import com.github.wegoo.cain.engine.params.KeyParamsEnum;
import java.security.Key;
import java.security.KeyPair;

public interface BaseProvider {

  void init(Object obj);

  KeyPair generateKeyPair(KeyParamsEnum keyParams);

  Key generateKey(KeyParamsEnum keyParams);


}
