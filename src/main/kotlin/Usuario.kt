import java.security.*
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Scanner
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

data class Usuario(val nombreUsuario: String, val passCifrada: SecretKey)

fun main() {
    val scanner = Scanner(System.`in`)
    var salir = true

    while (salir) {
        println("Bienvenido")
        println("1. Registrarse")
        println("2. Iniciar sesion")
        println("3. Salir")
        print("Selecciona una opción: ")
        when (scanner.nextInt()) {
            1 -> registrarUsuario(scanner)
            2 -> iniciarSesion(scanner)
            3 -> salir = false
            else -> println("Opcion incorrecta")
        }
    }
}

fun registrarUsuario(scanner: Scanner) {
    print("Ingresa el nombre de usuario: ")
    val nombreUsuario = scanner.next()
    print("Ingresa una contraseña: ")
    val contrasena = scanner.next()
    if (!validarContrasena(contrasena)) {
        throw IllegalArgumentException("Comprueba los requisitos minimos de seguridad de tu contraseña.")
    }

    val passCifrada = cifrarContrasena(contrasena)
    println("Usuario registrado correctamente")
    println("Nombre de usuario: $nombreUsuario")
    println("Contraseña cifrada: $passCifrada")
}

fun validarContrasena(contrasena: String): Boolean {
    val longitudMinima = 6
    val contieneNumero = Regex("[0-9]").containsMatchIn(contrasena)
    val contieneMayuscula = Regex("[A-Z]").containsMatchIn(contrasena)

    return contrasena.length >= longitudMinima &&
            contieneNumero &&
            contieneMayuscula
}

fun iniciarSesion(scanner: Scanner) {
    print("Ingrese su nombre de usuario: ")
    val nombreUsuario = scanner.next()
    print("Ingrese su contraseña: ")
    val contrasena = scanner.next()

    val passCifrada = cifrarContrasena(contrasena)
    println("Contraseña cifrada ingresada: $passCifrada")

}


fun cifrarContrasena(contrasena: String): String {
    val secretKey = generateSecretKey()
    val passCifrada = encryptWithAES(contrasena, secretKey.encoded)
    return passCifrada.joinToString(separator = ",") { it.toString() }
}

fun generateSecretKey(): SecretKey {
    val keyGenerator = KeyGenerator.getInstance("AES")
    keyGenerator.init(256)
    return keyGenerator.generateKey()
}
fun generateRSAKeyPair(): KeyPair {
    val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
    keyPairGenerator.initialize(2048) // Tamaño de la clave RSA
    return keyPairGenerator.generateKeyPair()
}

fun encryptWithRSA(data: ByteArray, publicKeyBytes: ByteArray): ByteArray {
    val publicKeySpec = X509EncodedKeySpec(publicKeyBytes)
    val keyFactory = KeyFactory.getInstance("RSA")
    val publicKey: PublicKey = keyFactory.generatePublic(publicKeySpec)

    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.ENCRYPT_MODE, publicKey)

    return cipher.doFinal(data)
}

fun decryptWithRSA(encryptedData: ByteArray, privateKeyBytes: ByteArray): ByteArray {
    val privateKeySpec = PKCS8EncodedKeySpec(privateKeyBytes)
    val keyFactory = KeyFactory.getInstance("RSA")
    val privateKey: PrivateKey = keyFactory.generatePrivate(privateKeySpec)

    val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
    cipher.init(Cipher.DECRYPT_MODE, privateKey)

    return cipher.doFinal(encryptedData)
}

fun encryptWithAES(data: String, secretKey: ByteArray): ByteArray {
    val secretKeySpec = SecretKeySpec(secretKey, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec)

    return cipher.doFinal(data.toByteArray())
}
fun decryptWithAES(encryptedData: ByteArray, secretKey: ByteArray): String {
    val secretKeySpec = SecretKeySpec(secretKey, "AES")
    val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec)

    val decryptedBytes = cipher.doFinal(encryptedData)
    return String(decryptedBytes)
}