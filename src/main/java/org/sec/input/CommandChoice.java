package org.sec.input;

import com.beust.jcommander.JCommander;
import org.sec.Constant.configuration;

/** [+] 根据命令自定义选项*/
public abstract class CommandChoice{
    public static boolean CommandChoice(Command command, JCommander jc) {
        if (command.help) {
            jc.usage();
            return true;
        }
        return false;
    }
}
