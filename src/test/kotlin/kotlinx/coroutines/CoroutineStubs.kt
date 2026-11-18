package kotlinx.coroutines

import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

interface CoroutineScope {
    val coroutineContext: CoroutineContext
}

object GlobalScope : CoroutineScope {
    override val coroutineContext: CoroutineContext = EmptyCoroutineContext
}

object Dispatchers {
    @JvmStatic
    val IO: CoroutineContext = EmptyCoroutineContext

    @JvmStatic
    val Default: CoroutineContext = EmptyCoroutineContext

    @JvmStatic
    val Unconfined: CoroutineContext = EmptyCoroutineContext
}
