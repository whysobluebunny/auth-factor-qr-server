package ru.mephi.abondarenko.auth.factor.qr.ui.hosted

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.springframework.stereotype.Service
import java.io.ByteArrayOutputStream
import java.util.*
import javax.imageio.ImageIO

@Service
class QrCodeRenderingService {

    fun renderDataUrl(content: String, size: Int = 320): String {
        val hints = mapOf(
            EncodeHintType.ERROR_CORRECTION to ErrorCorrectionLevel.M,
            EncodeHintType.MARGIN to 1
        )
        val matrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, size, size, hints)
        val image = java.awt.image.BufferedImage(size, size, java.awt.image.BufferedImage.TYPE_INT_RGB)

        for (x in 0 until size) {
            for (y in 0 until size) {
                image.setRGB(x, y, if (matrix.get(x, y)) 0x000000 else 0xFFFFFF)
            }
        }

        val output = ByteArrayOutputStream()
        ImageIO.write(image, "png", output)
        val base64 = Base64.getEncoder().encodeToString(output.toByteArray())
        return "data:image/png;base64,$base64"
    }
}
