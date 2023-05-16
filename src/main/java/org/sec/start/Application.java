package org.sec.start;

import com.beust.jcommander.JCommander;
import org.apache.log4j.Logger;
import org.sec.Constant.configuration;
import org.sec.Network.Socket;
import org.sec.input.Command;
import org.sec.input.CommandChoice;

import java.io.IOException;

public class Application {
    static boolean openFlag = false;
    private static final Logger logger = Logger.getLogger(Application.class);

    public static void start(String[] args) {
        Command command = new Command();
        JCommander jc = JCommander.newBuilder().addObject(command).build();
        jc.parse(args);

        CommandChoiceTest commandChoiceTest = new CommandChoiceTest(command, jc);
        if (commandChoiceTest.commandChoiceOverWrite(command, jc)) {
            logger.info("[-] Don't have this choice,Please repeat to choice!");
        }
        if (command.closeCheck) {
            configuration.closeCheck = true;
            Application.openFlag = true;
            Socket.connect(configuration.PORT);
        }
        if (!openFlag) {
            Socket.connect(configuration.PORT);
        }
    }

}

class CommandChoiceTest extends CommandChoice {
    public CommandChoiceTest(Command command, JCommander jc) {
        super();
    }

    /**
     * [+] 重写 命令选择
     */
    public boolean commandChoiceOverWrite(Command command, JCommander jc) {
        CommandChoice.CommandChoice(command, jc);
        return false;
    }
}
