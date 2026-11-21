package ccfb.hsm.cli

import ccfb.hsm.api.*
import ccfb.hsm.core.Hsm
import ccfb.hsm.crypto.RandomBytes
import ccfb.hsm.demo.DemoEnv
import ccfb.hsm.model.ErrorCode
import ccfb.hsm.model.HsmException
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.util.concurrent.Executors

/**
 * Minimal HTTP front end over [Hsm].
 *
 * Deliberately thin: it does transport concerns only (method/path routing, JSON in/out,
 * uniform error mapping). Every security decision lives in the service, so that the same
 * guarantees hold whether a caller uses HTTP or calls the object directly.
 *
 * The signed envelope is sent in headers:
 *   X-Client-Id, X-Timestamp-Ms, X-Nonce, X-Body-SHA256, X-MAC
 *
 * Errors are rendered as `{requestId, code, message}` where `message` is a generic constant
 * per code. Internal diagnostics are never serialised (see [ErrorCode]).
 */
object HttpApp {

    fun start(port: Int, env: DemoEnv): HttpServer {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", port), 0)
        server.executor = Executors.newFixedThreadPool(8)

        server.createContext("/") { ex -> handle(ex, env) }
        server.start()
        return server
    }

    private fun handle(ex: HttpExchange, env: DemoEnv) {
        val path = ex.requestURI.path
        val method = ex.requestMethod.uppercase()
        var requestId: String? = null
        try {
            val bodyBytes = ex.requestBody.readBytes()
            val body = bodyBytes.toString(Charsets.UTF_8)
            requestId = runCatching { Wire.mapper.readTree(body)["requestId"]?.asText() }.getOrNull()
            val envelope = SignedEnvelope(
                clientId = header(ex, "X-Client-Id"),
                timestampMs = header(ex, "X-Timestamp-Ms").toLongOrNull()
                    ?: throw HsmException(ErrorCode.UNAUTHENTICATED),
                nonce = header(ex, "X-Nonce"),
                bodySha256 = header(ex, "X-Body-SHA256"),
                mac = header(ex, "X-MAC")
            )
            val result = env.hsm.call(method, path, SignedCall(envelope, body))
            val json = Wire.toJson(result)
            ex.responseHeaders.add("Content-Type", "application/json; charset=utf-8")
            ex.responseHeaders.add("Cache-Control", "no-store")
            respond(ex, 200, json)
        } catch (e: HsmException) {
            respondError(ex, e.code, requestId)
        } catch (e: Exception) {
            respondError(ex, ErrorCode.INVALID_REQUEST, requestId)
        } finally {
            ex.close()
        }
    }

    private fun respondError(ex: HttpExchange, code: ErrorCode, requestId: String?) {
        ex.responseHeaders.add("Content-Type", "application/json; charset=utf-8")
        ex.responseHeaders.add("Cache-Control", "no-store")
        respond(ex, code.http, Wire.toJson(ErrorResponse(requestId, code.name, code.publicMessage)))
    }

    private fun respond(ex: HttpExchange, status: Int, json: String) {
        val bytes = json.toByteArray(Charsets.UTF_8)
        ex.sendResponseHeaders(status, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
    }

    private fun header(ex: HttpExchange, name: String): String =
        ex.requestHeaders.getFirst(name) ?: throw HsmException(ErrorCode.UNAUTHENTICATED)
}

/**
 * An interactive console that also exposes `--demo` for the adversarial suite and `--serve`
 * for HTTP. This is the only place that prints to stdout.
 */
fun main(args: Array<String>) {
    when (args.firstOrNull() ?: "--help") {
        "--serve" -> {
            val port = args.getOrNull(1)?.toIntOrNull() ?: 8443
            val env = DemoEnv().build()
            env.provision(env.cardVisa to "7315", env.cardOffset to "4826", env.cardAes to "9043")
            println("HSM simulator listening on http://127.0.0.1:$port")
            println("Telemetry: audit entries are appended for every call; check /v1/status as auditor.")
            HttpApp.start(port, env)
            Thread.currentThread().join()
        }
        "--demo" -> ccfb.hsm.attack.main()
        else -> {
            println("Usage: hsm [--serve [port] | --demo]")
            println("  --serve  run the HTTP front end (loopback only)")
            println("  --demo   run the adversarial probe suite and print the report")
        }
    }
}
