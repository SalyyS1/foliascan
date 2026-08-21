package com.salyvn.foliascan.scan

import org.objectweb.asm.ClassReader
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Handle
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes

/**
 * Turns a class file into a [ClassModel].
 *
 * Read-only: this never writes or transforms bytecode, and never loads the class. Debug info
 * is kept on purpose because line numbers are what make findings actionable.
 */
object ClassAnalyzer {

    /** @throws IllegalArgumentException when ASM cannot parse the bytes. */
    fun read(bytes: ByteArray): ClassModel {
        val collector = Collector()
        ClassReader(bytes).accept(collector, ClassReader.SKIP_FRAMES)
        return collector.build()
    }

    private class Collector : ClassVisitor(Opcodes.ASM9) {
        private var internalName: String = "?"
        private var superName: String? = null
        private var interfaceNames: List<String> = emptyList()
        private var sourceFile: String? = null
        private val methods = mutableListOf<MethodModel>()

        override fun visit(
            version: Int,
            access: Int,
            name: String,
            signature: String?,
            superName: String?,
            interfaces: Array<out String>?,
        ) {
            this.internalName = name
            this.superName = superName
            this.interfaceNames = interfaces?.toList() ?: emptyList()
        }

        override fun visitSource(source: String?, debug: String?) {
            sourceFile = source
        }

        override fun visitMethod(
            access: Int,
            name: String,
            descriptor: String,
            signature: String?,
            exceptions: Array<out String>?,
        ): MethodVisitor = MethodCollector(MethodId(name, descriptor), access) { methods += it }

        fun build(): ClassModel = ClassModel(
            internalName = internalName,
            superName = superName,
            interfaces = interfaceNames,
            sourceFile = sourceFile,
            methods = methods.toList(),
        )
    }

    private class MethodCollector(
        private val id: MethodId,
        private val access: Int,
        private val onDone: (MethodModel) -> Unit,
    ) : MethodVisitor(Opcodes.ASM9) {

        private val instructions = mutableListOf<Insn>()
        private var currentLine: Int? = null

        override fun visitLineNumber(line: Int, start: Label?) {
            currentLine = line
        }

        override fun visitMethodInsn(
            opcode: Int,
            owner: String,
            name: String,
            descriptor: String,
            isInterface: Boolean,
        ) {
            instructions += Insn(InsnKind.CALL, owner, name, descriptor, currentLine)
        }

        override fun visitInvokeDynamicInsn(
            name: String,
            descriptor: String,
            bootstrapMethodHandle: Handle?,
            vararg bootstrapMethodArguments: Any?,
        ) {
            // For LambdaMetafactory the implementation method is the sole Handle among the
            // bootstrap arguments; that handle points at the synthetic method holding the
            // lambda body, which is what we need in order to attribute code inside a lambda.
            val impl = bootstrapMethodArguments.filterIsInstance<Handle>().firstOrNull()
            instructions += Insn(
                kind = InsnKind.INDY,
                owner = impl?.owner ?: "?",
                name = name,
                desc = descriptor,
                line = currentLine,
                lambdaTarget = impl?.let { MethodKey(it.owner, MethodId(it.name, it.desc)) },
            )
        }

        override fun visitTypeInsn(opcode: Int, type: String) {
            instructions += Insn(InsnKind.TYPE_REF, type, opcodeName(opcode), "", currentLine)
        }

        override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
            instructions += Insn(InsnKind.FIELD, owner, name, descriptor, currentLine)
        }

        override fun visitEnd() {
            onDone(MethodModel(id, access, instructions.toList()))
        }

        private fun opcodeName(opcode: Int): String = when (opcode) {
            Opcodes.NEW -> "new"
            Opcodes.ANEWARRAY -> "anewarray"
            Opcodes.CHECKCAST -> "checkcast"
            Opcodes.INSTANCEOF -> "instanceof"
            else -> "type"
        }
    }
}
