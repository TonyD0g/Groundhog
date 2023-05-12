package org.sec.Crypt;

import org.sec.Constant.configuration;
import org.sec.utils.stringUtils;

import java.io.IOException;
import java.util.Random;

public class random {
    public static String randomVersion() {
        Random r = new Random();
        int randomNum = r.nextInt(4);
        return configuration.versionList[randomNum];
    }

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
     * 生成随机ThreadId增长数(小端存储)
     */
    public static String randomThreadIdIncrease() {
        int randomLength = Integer.parseInt(stringUtils.getRandomString("12", 1));
        StringBuilder stringBuilder = new StringBuilder();
        configuration.ThreadId = configuration.ThreadId + Integer.parseInt(stringUtils.getRandomString("0123456789", randomLength));

        String[] middleStr;
        if (configuration.ThreadId <= 255) {
            stringBuilder.append(String.format("%02x", configuration.ThreadId)).append("000000");
        } else if (configuration.ThreadId <= 65280) {
            middleStr = stringUtils.splitStr(String.format("%04x", configuration.ThreadId), 2);
            stringBuilder.append(middleStr[1]).append(middleStr[0]).append("0000");
        } else if (configuration.ThreadId <= 16711680) {
            middleStr = stringUtils.splitStr(String.format("%06x", configuration.ThreadId), 2);
            stringBuilder.append(middleStr[2]).append(middleStr[1]).append(middleStr[0]).append("0000");
        } else {
            middleStr = stringUtils.splitStr(String.format("%08x", configuration.ThreadId), 2);
            stringBuilder.append(middleStr[3]).append(middleStr[2]).append(middleStr[1]).append(middleStr[0]).append("0000");
        }
        return stringBuilder.toString();
    }
}
