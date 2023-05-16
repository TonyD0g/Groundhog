package org.sec.input;

import com.beust.jcommander.Parameter;
/** [+] 处理用户输入的参数 */
public  class Command {
    @Parameter(names = {"-h", "--help"}, description = "Help Info", help = true)
    public boolean help;

    @Parameter(names = {"-cc", "--CloseCheck"}, description = "is open password check?", help = true)
    public boolean closeCheck;
}
