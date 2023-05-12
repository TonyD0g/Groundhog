package org.sec;

import org.apache.log4j.Logger;
import org.sec.Constant.configuration;
import org.sec.Network.Socket;
import org.sec.input.Logo;
import org.sec.start.Application;

public class Main {
    private static final Logger logger = Logger.getLogger(Main.class);

    public static void main(String[] args) {

        Logo.PrintLogo();
        logger.info("start Groundhog-0.1.2 application");
        // 运行主逻辑
        Socket.connect(configuration.PORT);
        //Application.start(args);
    }
}