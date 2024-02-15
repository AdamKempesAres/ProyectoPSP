import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.FileInputStream
import java.security.KeyStore
import javax.net.ssl.*

class Servidor {
    fun main() {
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

        // Crear el socket SSL del servidor
        val sslServerSocketFactory = sslContext.serverSocketFactory
        val servidorSSL = sslServerSocketFactory.createServerSocket(puerto) as SSLServerSocket

        var clienteConectado: SSLSocket? = null
        var flujoEntrada: DataInputStream? = null
        var flujoSalida: DataOutputStream? = null

        for (i in 1..2) {
            println("Esperando al cliente $i")
            clienteConectado = servidorSSL.accept() as SSLSocket
            flujoEntrada = DataInputStream(clienteConectado.getInputStream())

            // El cliente me envía un mensaje
            println("Recibiendo del CLIENTE: $i \n\t${flujoEntrada.readUTF()}")

            flujoSalida = DataOutputStream(clienteConectado.getOutputStream())

            // Envío un saludo al cliente
            flujoSalida.writeUTF("Saludos al cliente del servidor")
        }
        // Cerrar streams y sockets
        flujoEntrada?.close()
        flujoSalida?.close()
        clienteConectado?.close()
        servidorSSL.close()
    }
}

fun main(args: Array<String>) {
    // Iniciar servidor
    val servidor = Servidor()
    servidor.main()
}