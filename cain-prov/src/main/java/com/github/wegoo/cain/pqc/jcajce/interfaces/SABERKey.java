package com.github.wegoo.cain.pqc.jcajce.interfaces;

import com.github.wegoo.cain.pqc.jcajce.spec.SABERParameterSpec;

import java.security.Key;

public interface SABERKey
    extends Key
{
    /**
     * Return the parameters for this key.
     *
     * @return a SABERParameterSpec
     */
    SABERParameterSpec getParameterSpec();
}
