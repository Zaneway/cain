package com.github.wegoo.cain.its;


import com.github.wegoo.cain.its.operator.ETSIDataDecryptor;
import com.github.wegoo.cain.oer.its.ieee1609dot2.AesCcmCiphertext;
import com.github.wegoo.cain.oer.its.ieee1609dot2.EncryptedData;
import com.github.wegoo.cain.oer.its.ieee1609dot2.EncryptedDataEncryptionKey;
import com.github.wegoo.cain.oer.its.ieee1609dot2.PKRecipientInfo;
import com.github.wegoo.cain.oer.its.ieee1609dot2.RecipientInfo;
import com.github.wegoo.cain.oer.its.ieee1609dot2.SymmetricCiphertext;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EccP256CurvePoint;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.EciesP256EncryptedKey;
import com.github.wegoo.cain.util.Arrays;

public class ETSIRecipientInfo
{
    private final RecipientInfo recipientInfo;
    private final EncryptedData encryptedData;

    public ETSIRecipientInfo(EncryptedData encryptedData, RecipientInfo recipientInfo)
    {
        this.recipientInfo = recipientInfo;
        this.encryptedData = encryptedData;
    }

    public ETSIRecipientInfo(RecipientInfo recipientInfo)
    {
        this.recipientInfo = recipientInfo;
        this.encryptedData = null;
    }

    public RecipientInfo getRecipientInfo()
    {
        return recipientInfo;
    }


    public EncryptedData getEncryptedData()
    {
        return encryptedData;
    }

    public byte[] getContent(ETSIDataDecryptor ddec)
    {
        if (SymmetricCiphertext.aes128ccm != encryptedData.getCiphertext().getChoice())
        {
            throw new IllegalArgumentException("Encrypted data is no AES 128 CCM");
        }

        AesCcmCiphertext act = AesCcmCiphertext.getInstance(encryptedData.getCiphertext().getSymmetricCiphertext());

        // Test it is the correct kind of recipient info.
        PKRecipientInfo pkRecipientInfo = PKRecipientInfo.getInstance(recipientInfo.getRecipientInfo());
        EncryptedDataEncryptionKey edec = pkRecipientInfo.getEncKey();

        EciesP256EncryptedKey key = EciesP256EncryptedKey.getInstance(edec.getEncryptedDataEncryptionKey());
        EccP256CurvePoint point = EccP256CurvePoint.getInstance(key.getV());

        // [ephemeral public key][encrypted key][tag]
        byte[] wrappedKey = Arrays.concatenate(point.getEncodedPoint(), key.getC().getOctets(), key.getT().getOctets());

        return ddec.decrypt(wrappedKey, act.getCcmCiphertext().getContent(), act.getNonce().getOctets());
    }


}
