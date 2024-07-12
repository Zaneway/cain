package com.github.wegoo.cain.math.ec.endo;

import com.github.wegoo.cain.math.ec.ECPointMap;

public interface ECEndomorphism
{
    ECPointMap getPointMap();

    boolean hasEfficientPointMap();
}
