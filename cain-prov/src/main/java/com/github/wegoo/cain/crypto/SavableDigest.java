package com.github.wegoo.cain.crypto;

import com.github.wegoo.cain.crypto.digests.EncodableDigest;
import com.github.wegoo.cain.util.Memoable;

/**
 * Extended digest which provides the ability to store state and
 * provide an encoding.
 */
public interface SavableDigest
    extends ExtendedDigest, EncodableDigest, Memoable
{
}
