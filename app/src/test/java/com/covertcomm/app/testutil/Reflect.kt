package com.covertcomm.app.testutil

import java.lang.reflect.Field
import java.lang.reflect.Method

object Reflect {

    fun field(target: Any, name: String): Any? {
        var cls: Class<*>? = target.javaClass
        while (cls != null) {
            try {
                val f: Field = cls.getDeclaredField(name)
                f.isAccessible = true
                return f.get(target)
            } catch (_: NoSuchFieldException) {
                cls = cls.superclass
            }
        }
        throw NoSuchFieldException(name)
    }

    @Suppress("UNCHECKED_CAST")
    fun <T> set(target: Any, name: String, value: T) {
        var cls: Class<*>? = target.javaClass
        while (cls != null) {
            try {
                val f: Field = cls.getDeclaredField(name)
                f.isAccessible = true
                f.set(target, value)
                return
            } catch (_: NoSuchFieldException) {
                cls = cls.superclass
            }
        }
        throw NoSuchFieldException(name)
    }

    fun call(target: Any, name: String, vararg args: Any?): Any? {
        val types = args.map { it?.javaClass }.toTypedArray()
        var cls: Class<*>? = target.javaClass
        while (cls != null) {
            for (m in cls.declaredMethods) {
                if (m.name != name) continue
                if (m.parameterTypes.size != args.size) continue
                if (!matches(m, args)) continue
                m.isAccessible = true
                return m.invoke(target, *args)
            }
            cls = cls.superclass
        }
        throw NoSuchMethodException("$name(${types.joinToString { it?.name ?: "null" }})")
    }

    private fun matches(m: Method, args: Array<out Any?>): Boolean {
        val params = m.parameterTypes
        for (i in params.indices) {
            val a = args[i] ?: continue
            val p = params[i]
            if (p.isPrimitive) {
                val boxed = when (p.name) {
                    "int" -> Integer::class.java
                    "long" -> java.lang.Long::class.java
                    "boolean" -> java.lang.Boolean::class.java
                    "byte" -> java.lang.Byte::class.java
                    "short" -> java.lang.Short::class.java
                    "float" -> java.lang.Float::class.java
                    "double" -> java.lang.Double::class.java
                    "char" -> Character::class.java
                    else -> p
                }
                if (!boxed.isInstance(a)) return false
            } else if (!p.isInstance(a)) {
                return false
            }
        }
        return true
    }
}