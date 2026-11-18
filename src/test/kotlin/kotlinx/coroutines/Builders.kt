@file:JvmName("BuildersKt")

package kotlinx.coroutines

import kotlin.coroutines.CoroutineContext

fun launch(
    scope: CoroutineScope,
    context: CoroutineContext,
    block: suspend CoroutineScope.() -> Unit,
): Any = Any()

suspend fun <T> withContext(
    context: CoroutineContext,
    block: suspend CoroutineScope.() -> T,
): T = throw UnsupportedOperationException()
