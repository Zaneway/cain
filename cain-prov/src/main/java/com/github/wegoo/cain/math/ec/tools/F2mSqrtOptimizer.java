package com.github.wegoo.cain.math.ec.tools;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.SortedSet;
import java.util.TreeSet;

import com.github.wegoo.cain.asn1.x9.ECNamedCurveTable;
import com.github.wegoo.cain.asn1.x9.X9ECParametersHolder;
import com.github.wegoo.cain.crypto.ec.CustomNamedCurves;
import com.github.wegoo.cain.math.ec.ECAlgorithms;
import com.github.wegoo.cain.math.ec.ECCurve;
import com.github.wegoo.cain.math.ec.ECFieldElement;
import com.github.wegoo.cain.util.Strings;

public class F2mSqrtOptimizer
{
    public static void main(String[] args)
    {
        SortedSet names = new TreeSet(enumToList(ECNamedCurveTable.getNames()));
        names.addAll(enumToList(CustomNamedCurves.getNames()));

        Iterator it = names.iterator();
        while (it.hasNext())
        {
            String name = (String)it.next();
            X9ECParametersHolder x9 = CustomNamedCurves.getByNameLazy(name);
            if (x9 == null)
            {
                x9 = ECNamedCurveTable.getByNameLazy(name);
            }
            if (x9 != null)
            {
                ECCurve curve = x9.getCurve();
                if (ECAlgorithms.isF2mCurve(curve))
                {
                    // -DM System.out.println
                    System.out.print(name + ":");
                    implPrintRootZ(curve);
                }
            }
        }
    }

    public static void printRootZ(ECCurve curve)
    {
        if (!ECAlgorithms.isF2mCurve(curve))
        {
            throw new IllegalArgumentException("Sqrt optimization only defined over characteristic-2 fields");
        }

        implPrintRootZ(curve);
    }

    private static void implPrintRootZ(ECCurve curve)
    {
        ECFieldElement z = curve.fromBigInteger(BigInteger.valueOf(2));
        ECFieldElement rootZ = z.sqrt();

        // -DM System.out.println
        System.out.println(Strings.toUpperCase(rootZ.toBigInteger().toString(16)));

        if (!rootZ.square().equals(z))
        {
            throw new IllegalStateException("Optimized-sqrt sanity check failed");
        }
    }

    private static List enumToList(Enumeration en)
    {
        List rv = new ArrayList();
        while (en.hasMoreElements())
        {
            rv.add(en.nextElement());
        }
        return rv;
    }
}
