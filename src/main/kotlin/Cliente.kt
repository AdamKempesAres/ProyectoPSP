import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.security.KeyStore
import javax.net.ssl.*

class Cliente {
    fun main() {
        val host = "localhost"
        val puerto = 5556
        val keyStorePath = "C:\\Users\\aadaa\\IdeaProjects\\ProyectoPSP\\AlmacenSrv"
        val keyStorePassword = "1234567"
        val keyPassword = "1234567"

        // Cargar el almacén de claves
        val keyStore = KeyStore.getInstance("JKS")
        keyStore.load(FileInputStream(keyStorePath), keyStorePassword.toCharArray())

        // Configurar el administrador de claves
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, keyPassword.toCharArray())

        // Configurar el administrador de confianza
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(keyStore)

        // Configurar el contexto SSL
        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(keyManagerFactory.keyManagers, trustManagerFactory.trustManagers, null)

        // Crear el socket SSL del cliente
        val sslSocketFactory = sslContext.socketFactory
        val cliente = sslSocketFactory.createSocket(host, puerto) as SSLSocket

        // Creo flujo de salida al servidor
        val flujoSalida = DataOutputStream(cliente.getOutputStream())

        // Envío un saludo al servidor
        flujoSalida.writeUTF("Saludos al SERVIDOR DESDE EL CLIENTE")

        // Creo flujo de entrada al servidor
        val flujoEntrada = DataInputStream(cliente.getInputStream())

        // El servidor me envía un mensaje
        println("Recibiendo del SERVIDOR: \n\t${flujoEntrada.readUTF()}")

        // Cerrar streams y sockets
        flujoEntrada.close()
        flujoSalida.close()
        cliente.close()
    }
}

fun main(args: Array<String>) {
    // Iniciar cliente
    val cliente = Cliente()
    cliente.main()
}