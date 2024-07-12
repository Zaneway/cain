package com.github.wegoo.cain.pqc.jcajce.interfaces;

import java.security.PublicKey;

public interface NHPublicKey
    extends NHKey, PublicKey
{
    byte[] getPublicData();
}
