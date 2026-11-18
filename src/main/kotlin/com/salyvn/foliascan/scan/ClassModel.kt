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

    private val directSubtypes: Map<String, Set<String>> by lazy {
        val index = LinkedHashMap<String, MutableSet<String>>()
        for (model in classes.values) {
            model.superName?.let { parent ->
                if (classes.containsKey(parent)) {
                    index.getOrPut(parent) { linkedSetOf() }.add(model.internalName)
                }
            }
            for (iface in model.interfaces) {
                if (classes.containsKey(iface)) {
                    index.getOrPut(iface) { linkedSetOf() }.add(model.internalName)
                }
            }
        }
        index
    }

    fun get(internalName: String): ClassModel? = classes[internalName]

    fun contains(internalName: String): Boolean = classes.containsKey(internalName)

    /** All transitive in-jar subclasses and interface implementations of [internalName]. */
    fun subtypesOf(internalName: String): Set<String> {
        val out = linkedSetOf<String>()
        val queue = ArrayDeque<String>()
        directSubtypes[internalName]?.forEach { queue.addLast(it) }
        while (queue.isNotEmpty()) {
            val cur = queue.removeFirst()
            if (!out.add(cur)) continue
            directSubtypes[cur]?.forEach { queue.addLast(it) }
        }
        return out
    }

    /**
     * Class Hierarchy Analysis (CHA) call-target resolver for in-jar invocations.
     *
     * Resolves inherited superclass/default-interface methods upward and, for virtual or
     * interface dispatch (`INVOKEVIRTUAL` / `INVOKEINTERFACE`), resolves concrete subtype
     * implementations downward up to [maxPolymorphicTargets] concrete targets so interface-driven
     * services propagate thread-affinity taint without cross-wiring mega-interfaces.
     */
    fun resolveCallTargets(insn: Insn, maxPolymorphicTargets: Int = 8): List<MethodKey> {
        if (insn.kind != InsnKind.CALL || !contains(insn.owner)) return emptyList()
        if (insn.name == "<clinit>") return emptyList()

        val targetId = MethodId(insn.name, insn.desc)
        val out = linkedSetOf<MethodKey>()

        // 1. Direct or upward inherited concrete method (superclasses, then default interfaces)
        findInheritedConcreteMethod(insn.owner, targetId)?.let { out += it }

        // 2. Downward polymorphic dispatch for INVOKEINTERFACE (185) and INVOKEVIRTUAL (182)
        val isPolymorphic = insn.name != "<init>" &&
            (insn.opcode == 185 || insn.opcode == 182 || insn.opcode == 0)
        if (isPolymorphic) {
            val concreteOverrides = mutableListOf<MethodKey>()
            for (sub in subtypesOf(insn.owner)) {
                val subModel = classes[sub] ?: continue
                val m = subModel.method(targetId) ?: continue
                // Skip ACC_ABSTRACT (0x0400) and ACC_BRIDGE (0x0040) synthetic forwarders
                if ((m.access and 0x0400) != 0 || (m.access and 0x0040) != 0) continue
                if (m.instructions.isEmpty()) continue
                concreteOverrides += MethodKey(sub, m.id)
            }
            if (concreteOverrides.size <= maxPolymorphicTargets) {
                out.addAll(concreteOverrides)
            }
        }
        return out.toList()
    }

    private fun findInheritedConcreteMethod(owner: String, targetId: MethodId): MethodKey? {
        val direct = classes[owner]?.method(targetId)
        if (direct != null && (direct.access and 0x0400) == 0 && direct.instructions.isNotEmpty()) {
            return MethodKey(owner, direct.id)
        }
        if (targetId.name == "<init>") return null
        for (sup in superChain(owner)) {
            val m = classes[sup]?.method(targetId)
            if (m != null && (m.access and 0x0400) == 0 && m.instructions.isNotEmpty()) {
                return MethodKey(sup, m.id)
            }
        }
        val visitedIfaces = mutableSetOf<String>()
        val queue = ArrayDeque<String>()
        classes[owner]?.interfaces?.forEach { queue.addLast(it) }
        superChain(owner).forEach { sup -> classes[sup]?.interfaces?.forEach { queue.addLast(it) } }
        while (queue.isNotEmpty()) {
            val iface = queue.removeFirst()
            if (!visitedIfaces.add(iface)) continue
            val ifaceModel = classes[iface] ?: continue
            val m = ifaceModel.method(targetId)
            if (m != null && (m.access and 0x0400) == 0 && m.instructions.isNotEmpty()) {
                return MethodKey(iface, m.id)
            }
            ifaceModel.interfaces.forEach { queue.addLast(it) }
        }
        return null
    }

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
