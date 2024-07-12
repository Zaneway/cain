package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

public interface SPHINCSKey
    extends Key
{
    byte[] getKeyData();
}
