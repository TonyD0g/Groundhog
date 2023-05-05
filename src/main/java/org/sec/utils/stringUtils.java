package org.sec.utils;

import javax.xml.bind.DatatypeConverter;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class stringUtils {
    public static void main(String[] args) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        //generatePassword();
    }

    /**
     * 依据Mysql文档对通讯过程的密码进行生成
     */
    public static byte[] generatePassword(String password, String slat) throws NoSuchAlgorithmException {
        byte[] buff = passwordHashStage1(password);

        byte[] passwordHash = new byte[buff.length];
        System.arraycopy(buff, 0, passwordHash, 0, buff.length);
        passwordHash = passwordHashStage2(passwordHash, hexToByteArray(slat));

        byte[] packetDataAfterSalt = new byte[20];
        System.arraycopy(hexToByteArray(slat), 0, packetDataAfterSalt, 0, 20);
        byte[] mysqlScrambleBuff = new byte[20];

        xorString(packetDataAfterSalt, mysqlScrambleBuff, passwordHash, 20);
        xorString(mysqlScrambleBuff, buff, buff, 20);

        // 最后发送buff即可
        return buff;
    }

    public static void xorString(byte[] from, byte[] to, byte[] scramble, int length) {
        int pos = 0;

        for (int scrambleLength = scramble.length; pos < length; ++pos) {
            to[pos] = (byte) (from[pos] ^ scramble[pos % scrambleLength]);
        }

    }

    /**
     * 实现类似于php的sha1函数
     */
    public static byte[] passwordHashStage1(String password) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        StringBuilder cleansedPassword = new StringBuilder();
        int passwordLength = password.length();

        for (int i = 0; i < passwordLength; ++i) {
            char c = password.charAt(i);
            if (c != ' ' && c != '\t') {
                cleansedPassword.append(c);
            }
        }

        return md.digest(getBytes(cleansedPassword.toString()));
    }

    public static byte[] getBytes(String value) {
        String platformEncoding = System.getProperty("file.encoding");
        try {
            return getBytes((String) value, 0, value.length(), platformEncoding);
        } catch (UnsupportedEncodingException var2) {
            return null;
        }
    }

    public static byte[] getBytes(String value, int offset, int length, String encoding) throws UnsupportedEncodingException {
        Charset cs = StandardCharsets.UTF_8; // findCharset(encoding);
        ByteBuffer buf = cs.encode(CharBuffer.wrap(value.toCharArray(), offset, length));
        int encodedLen = buf.limit();
        byte[] asBytes = new byte[encodedLen];
        buf.get(asBytes, 0, encodedLen);
        return asBytes;
    }

    public static byte[] passwordHashStage2(byte[] hashedPassword, byte[] salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(salt, 0, 4);
        md.update(hashedPassword, 0, 20);
        return md.digest();
    }


    /**
     * Hex Stream直接转为byte数组,类似于python的 b"\x12"
     *
     * @return
     */
    public static byte[] hexToByteArray(String hexString) {
        return DatatypeConverter.parseHexBinary(hexString); // 转换为字节数组
    }

    public static void x1(String str) {
        String[] test = stringUtils.splitStr(str, 2);
        StringBuilder stringBuilder = new StringBuilder();
        for (String j : test) {
            // stringBuilder.append("0x" + j + ",");
            stringBuilder.append("\\x" + j);
        }
        System.out.println(stringBuilder);
    }

    /**
     * 两个byte数组进行合并为一个byte数组
     */
    public static byte[] byteMerger(byte[] bt1, byte[] bt2) {
        byte[] bt3 = new byte[bt1.length + bt2.length];
        System.arraycopy(bt1, 0, bt3, 0, bt1.length);
        System.arraycopy(bt2, 0, bt3, bt1.length, bt2.length);
        return bt3;
    }

    /**
     * 将\x开头的16进制转换为不带\x
     */
    public static String decodeX(String str) throws UnsupportedEncodingException {
        String s1 = str.replaceAll("\\\\x", "%");
        return URLDecoder.decode(s1, "utf-8");
    }

    /**
     * 将string转为\x开头的16进制字符串
     */
    public static String parseStringToX(String str) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte aloneByte : str.getBytes(StandardCharsets.UTF_8)) {
            stringBuilder.append("\\x" + Integer.toHexString(aloneByte));
        }
        return stringBuilder.toString();
    }

    /**
     * 返回被 几几分割 的数组
     */
    public static String[] splitStr(String str, int splitNum) {
        int splitLength = 0;
        if (str.length() % 2 != 0) {
            splitLength = (str.length() / 2) + 1;
        } else {
            splitLength = (str.length() / 2);
        }
        String[] strings = new String[splitLength];
        for (int i = 0; i < splitLength; i++) {
            strings[i] = str.substring(i, i + splitNum);
        }
        return strings;
    }


    /**
     * 根据长度返回随机字符串
     */
    public static String getRandomString(String randomList, int length) {
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < length; i++) {
            int number = random.nextInt(randomList.length());
            sb.append(randomList.charAt(number));
        }
        return sb.toString();
    }

    /**
     * 依据某个符号进行分割,如 splitBySymbol("A-B","-") 切割为 A和B
     */
    public static String[] splitBySymbol(String str, String regex) {
        return str.split(regex);
    }

    /**
     * 对类型进行处理,如Ljava.lang.Object;中的L和java.lang.Object
     *
     * @return
     */
    public static String[] handleFieldType(String str) {
        /* 如Ljava.lang.Object;  就要被拆开为  L java.lang.Object ;
         主要有这几种类型: B - byte，C - char，D - double，F - float，I - int，J - long，S - short，Z - boolean，V - void，L - 对象类型( 如Ljava/lang/String; )，数组 - 每一个维度前置使用[表示
           (这几种类型可以随意组合!,所以要做好对应的处理,如 IL java/lang/String;)
        */
        String[] tmpFieldType = new String[2];

        // 这里可能写的有问题,我的写法是: 判断"java"在字符串中的位置,然后以此进行分割字符串
        int index = str.indexOf("java");
        if (index > 0) {
            tmpFieldType[0] = str.substring(0, index);
            tmpFieldType[1] = str.substring(index, str.length() - 1);
        } else {
            tmpFieldType[0] = str.substring(0, 1);
            tmpFieldType[1] = str.substring(1, str.length() - 1);
        }
        // ILO => IL 0 3个
        System.out.println(tmpFieldType[0].getBytes(StandardCharsets.UTF_8).length);
        String[] fieldType = new String[tmpFieldType[0].getBytes(StandardCharsets.UTF_8).length + 1];
        // 如 ILjava/lang/String; 将 java/lang/String 存放到 fieldType 末尾槽位
        fieldType[fieldType.length - 1] = tmpFieldType[1];
        // 将类型从头存放到 fieldType
        for (int i = 0; i < fieldType.length - 1; i++) {
            fieldType[i] = tmpFieldType[0].substring(0, i);
        }
        return fieldType;
    }

    /**
     * 对某些符号进行相应替换
     */
    public static String replaceCharacter(String str) {
        return str.replace("/", ".");
    }

    /**
     * unicode编码文件名,以使编译前后文件名一致
     */
    private static StringBuilder decodePath(String name) {
        String[] jspNameArr = name.split("_");
        StringBuilder afterDecodeName = new StringBuilder();
        int num = 0;
        for (String part : jspNameArr) {
            String afterDecode = null;
            if (part.length() >= 4) {
                try {
                    afterDecode = decodeUnicode("\\u" + part.substring(0, 4));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            if (part.length() >= 4 && afterDecode != null && ("\\u" + part.substring(0, 4)).equals(unicodeEncoding(afterDecode))) {
                afterDecodeName.append(afterDecode);
                afterDecodeName.append(part.substring(4));
            } else {
                if (num != 0) {
                    afterDecodeName.append(".");
                }
                afterDecodeName.append(part);
            }
            ++num;
        }
        return afterDecodeName;
    }

    private static String decodeUnicode(final String dataStr) {
        int start = 0;
        int end = 0;
        final StringBuilder buffer = new StringBuilder();
        while (start > -1) {
            end = dataStr.indexOf("\\u", start + 2);
            String charStr;
            if (end == -1) {
                charStr = dataStr.substring(start + 2);
            } else {
                charStr = dataStr.substring(start + 2, end);
            }
            char letter = 0;
            int flag = 0;
            try {
                letter = (char) Integer.parseInt(charStr, 16); // 16进制转为int,int转char
                flag = 1;
            } catch (Exception ignored) {

            }
            if (flag == 1) {
                buffer.append(letter);
            } else {
                buffer.append(charStr);
            }
            start = end;
        }
        return buffer.toString();
    }

    public static String reductionRelativePath(String path, String root) {
        String separator = "/|\\\\";
        String encodeRelativePath = path.substring(root.length() + 1);
        String[] names;
        names = encodeRelativePath.split(separator);                    //兼容windows和linux的分隔符
        StringBuilder relativePath = new StringBuilder();
        for (String name : names) {
            if (name.length() != 0) {
                relativePath.append(decodePath(name));
                relativePath.append(File.separator);
            }
        }
        return relativePath.substring(0, relativePath.length() - 1);         //抛弃最后一个\\
    }

    /**
     * unicode编码
     */
    private static String unicodeEncoding(final String gbString) {
        char[] utfBytes = gbString.toCharArray();
        StringBuilder unicodeBytes = new StringBuilder();
        for (char utfByte : utfBytes) {
            String hexB = Integer.toHexString(utfByte);
            if (hexB.length() <= 2) {
                hexB = "00" + hexB;
            }
            unicodeBytes.append("\\u").append(hexB);
        }
        return unicodeBytes.toString();
    }

    /**
     * 返回当前时间(yyyy-MM-dd HH:mm:ss)
     */
    public static String thisTime() {
        Date date = new Date();
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss");
        return dateFormat.format(date);
    }

    /**
     * 改变时间,如让时间加10分钟
     */
    public static String changeTime(Date thisTime, long minutes) {
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        minutes = minutes * 60 * 1000;
        Date afterDate = new Date(thisTime.getTime() + minutes);//30分钟后的时间
        return dateFormat.format(afterDate);
    }

}

