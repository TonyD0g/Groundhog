package org.sec.utils.test;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.common.BitMatrix;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.File;
import java.io.IOException;

public class QRcodeImageUtil {

    private static final int BLACK = 0xFF000000;
    private static final int WHITE = 0xFFFFFFFF;
    public static void main(String[] args) throws Exception {
        String content = "weixin://findfriend/verifycontact/wxid_9mu4cw0h7out22";
        String path = "D:\\";
        String filename = "test";
        QRcodeImageUtil .buildQuickMark(content, path, filename);
        System.out.println("done");
    }

    /**
     * 根据字符串生成对应的二维码图片png
     * 大小:200*200
     * <p>
     * content：要转换的内容
     * path：生成的二维码图片的绝对路径
     * filename: 生成的文件名
     */
    public static void buildQuickMark(String content, String path, String filename) throws Exception {
        try {
            BitMatrix byteMatrix = new MultiFormatWriter().encode(new String(content.getBytes(), "iso-8859-1"),
                    BarcodeFormat.QR_CODE, 200, 200);
            String format = "png";
            File file = new File(path + "\\" + filename + "." + format);
            BufferedImage image = toBufferedImage(byteMatrix);
            if (!ImageIO.write(image, format, file)) {
                throw new IOException("Could not write an image of format " + format + " to " + file);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static BufferedImage toBufferedImage(BitMatrix matrix) {
        int width = matrix.getWidth();
        int height = matrix.getHeight();
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        for (int x = 0; x < width; x++) {
            for (int y = 0; y < height; y++) {
                image.setRGB(x, y, matrix.get(x, y) ? BLACK : WHITE);
            }
        }
        return image;
    }
}

