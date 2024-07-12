package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.Key;

import com.github.wegoo.cain.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

public interface SPHINCSPlusKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SPHINCSPlusParameterSpec
     */
    SPHINCSPlusParameterSpec getParameterSpec();
}
