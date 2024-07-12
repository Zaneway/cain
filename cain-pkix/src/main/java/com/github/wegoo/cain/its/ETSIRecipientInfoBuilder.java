package com.github.wegoo.cain.its;

import com.github.wegoo.cain.oer.its.ieee1609dot2.PKRecipientInfo;
import com.github.wegoo.cain.oer.its.ieee1609dot2.RecipientInfo;
import com.github.wegoo.cain.oer.its.ieee1609dot2.basetypes.HashedId8;

public class ETSIRecipientInfoBuilder
{

    private final ETSIKeyWrapper keyWrapper;
    private final byte[] recipientID;

    public ETSIRecipientInfoBuilder(ETSIKeyWrapper keyWrapper, byte[] recipientID)
    {
        this.keyWrapper = keyWrapper;
        this.recipientID = recipientID;
    }


    public RecipientInfo build(byte[] secretKey)
    {
        try
        {
            return RecipientInfo.certRecipInfo(PKRecipientInfo.builder()
                .setRecipientId(new HashedId8(recipientID))
                .setEncKey(keyWrapper.wrap(secretKey))
                .createPKRecipientInfo());
        }
        catch (Exception ex)
        {
            throw new RuntimeException(ex.getMessage(), ex);
        }

    }


}
