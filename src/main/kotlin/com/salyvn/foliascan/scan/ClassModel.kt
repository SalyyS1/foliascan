package com.salyvn.foliascan.scan

/** A method identified within a class: name plus JVM descriptor. */
data class MethodId(val name: String, val desc: String) {
    override fun toString(): String = "$name$desc"
}

/** Fully qualified method identity across the jar. */
data class MethodKey(val owner: String, val method: MethodId) {
    override fun toString(): String = "$owner.$method"
}

enum class InsnKind {
    /** invokevirtual / invokestatic / invokeinterface / invokespecial. */
    CALL,

    /** invokedynamic - carries the synthetic lambda implementation it targets. */
    INDY,

    /** new / checkcast / instanceof / anewarray. */
    TYPE_REF,

    /** getfield / putfield / getstatic / putstatic. */
    FIELD,

    /** ldc string literal, used to detect Class.forName Folia runtime probes. */
    LDC_STRING,

    /** monitorenter instruction indicating synchronized block protection. */
    MONITOR,

    /** aconst_null instruction indicating a null parameter or reference. */
    NULL_CONST,

    /** pop / pop2 instruction discarding a stack operand (e.g. unhandled return value). */
    STACK_POP,

    /** aload / astore local variable reference instruction for intra-method value tracking. */
    VAR,
}

/**
 * One interesting instruction. Order within [MethodModel.instructions] is preserved because
 * the async-context heuristics rely on "the lambda or object created immediately before this
 * call is the task being handed to it".
 */
data class Insn(
    val kind: InsnKind,
    val owner: String,
    val name: String,
    val desc: String,
    val line: Int?,
    /** For [InsnKind.INDY]: the synthetic method the lambda body compiled into. */
    val lambdaTarget: MethodKey? = null,
    /** Raw JVM opcode when distinguishing getstatic/putstatic or monitorenter matters. */
    val opcode: Int = 0,
)

data class FieldModel(
    val name: String,
    val desc: String,
    val access: Int,
)

data class MethodModel(
    val id: MethodId,
    val access: Int,
    val instructions: List<Insn>,
    val flowInstructions: List<Insn> = instructions,
)

data class ClassModel(
    val internalName: String,
    val superName: String?,
    val interfaces: List<String>,
    val sourceFile: String?,
    val methods: List<MethodModel>,
    val fields: List<FieldModel> = emptyList(),
) {
    val binaryName: String get() = internalName.replace('/', '.')

    fun method(id: MethodId): MethodModel? = methods.firstOrNull { it.id == id }
}

/** Everything read out of one jar's class files, keyed by internal name. */
class JarClasses(val classes: Map<String, ClassModel>) {
    fun get(internalName: String): ClassModel? = classes[internalName]

    fun contains(internalName: String): Boolean = classes.containsKey(internalName)

    /** Walks up the superclass chain within this jar, stopping at the first unknown type. */
    fun superChain(internalName: String): List<String> {
        val out = mutableListOf<String>()
        var current = classes[internalName]?.superName
        val seen = mutableSetOf(internalName)
        while (current != null && seen.add(current)) {
            out += current
            current = classes[current]?.superName
        }
        return out
    }

    /** True when [internalName] extends [supertype], directly or through classes in this jar. */
    fun extends(internalName: String, supertype: String): Boolean =
        classes[internalName]?.superName == supertype || supertype in superChain(internalName)

    /**
     * True when [internalName] extends or implements any type in [targets], walking known
     * superclasses and interfaces inside this jar.
     */
    fun inheritsAny(internalName: String, targets: Set<String>): Boolean {
        val visited = mutableSetOf<String>()
        val queue = ArrayDeque<String>()
        queue.addLast(internalName)
        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            if (!visited.add(cur)) continue
            if (cur != internalName && cur in targets) return true
            val model = classes[cur] ?: continue
            model.superName?.let {
                if (it in targets) return true
                queue.addLast(it)
            }
            for (iface in model.interfaces) {
                if (iface in targets) return true
                queue.addLast(iface)
            }
        }
        return false
    }
}
