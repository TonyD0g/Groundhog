package org.sec.Crypt;

import org.sec.Constant.configuration;
import org.sec.utils.stringUtils;

import java.io.IOException;

public class random {

    public static String randomSalt() {
        StringBuilder saltByte = new StringBuilder(new String());
        String middleByte1;
        for (int i = 0; i < 20; i++) {
            middleByte1 = stringUtils.getRandomString("0123456789", 2);
            saltByte.append(middleByte1);
        }
        return saltByte.toString();
    }

    /**
     * 生成随机ThreadId增长数
     */
    public static String randomThreadIdIncrease() throws IOException {
        int randomLength = Integer.parseInt(stringUtils.getRandomString("12", 1));
        StringBuilder stringBuilder = new StringBuilder();
        configuration.ThreadId = configuration.ThreadId + Integer.parseInt(stringUtils.getRandomString("0123456789", randomLength));

        if (configuration.ThreadId <= 255) {
            stringBuilder.append(String.format("%02x", configuration.ThreadId)).append("000000");
        } else if (configuration.ThreadId <= 65280) {
            stringBuilder.append(String.format("%04x", configuration.ThreadId)).append("0000");
        } else if (configuration.ThreadId <= 16711680) {
            stringBuilder.append(String.format("%06x", configuration.ThreadId)).append("00");
        } else {
            stringBuilder.append(String.format("%08x", configuration.ThreadId));
        }
        return stringBuilder.toString();
    }
}
