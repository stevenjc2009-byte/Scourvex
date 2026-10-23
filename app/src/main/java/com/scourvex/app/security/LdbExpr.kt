package com.scourvex.app.security

/**
 * ClamAV logical signature expression, e.g. `(0&1)|2=0` or `0>2,1`.
 * Each node yields (count = total matches, distinct = how many different subsigs matched).
 * Modifiers: =X, =X,Y, >X, >X,Y, <X, <X,Y — X tests count, Y tests distinct.
 */
sealed class LdbExpr {
    class Res(val count: Int, val distinct: Int)

    abstract fun eval(c: IntArray): Res
    abstract fun maxIndex(): Int

    class Leaf(val i: Int) : LdbExpr() {
        override fun eval(c: IntArray) = Res(c[i], if (c[i] > 0) 1 else 0)
        override fun maxIndex() = i
    }

    class Bin(val and: Boolean, val l: LdbExpr, val r: LdbExpr) : LdbExpr() {
        override fun eval(c: IntArray): Res {
            val a = l.eval(c)
            val b = r.eval(c)
            val ok = if (and) a.count > 0 && b.count > 0 else a.count > 0 || b.count > 0
            return if (ok) Res(a.count + b.count, a.distinct + b.distinct) else Res(0, 0)
        }
        override fun maxIndex() = maxOf(l.maxIndex(), r.maxIndex())
    }

    class Mod(val e: LdbExpr, val op: Char, val x: Int, val y: Int?) : LdbExpr() {
        override fun eval(c: IntArray): Res {
            val r = e.eval(c)
            val ok = when (op) {
                '=' -> r.count == x && (y == null || r.distinct >= y)
                '>' -> r.count > x && (y == null || r.distinct > y)
                else -> r.count < x && (y == null || r.distinct < y)
            }
            // A satisfied "=0" (sub must be absent) still has to count as true upstream.
            return if (ok) Res(maxOf(r.count, 1), maxOf(r.distinct, 1)) else Res(0, 0)
        }
        override fun maxIndex() = e.maxIndex()
    }

    companion object {
        fun parse(s: String): LdbExpr? = runCatching {
            val p = Parser(s.filterNot { it.isWhitespace() })
            val e = p.expr()
            if (p.i != p.s.length) null else e
        }.getOrNull()
    }

    private class Parser(val s: String) {
        var i = 0

        fun expr(): LdbExpr {
            var left = term()
            while (i < s.length && (s[i] == '&' || s[i] == '|')) {
                val and = s[i++] == '&'
                left = Bin(and, left, term())
            }
            return left
        }

        fun term(): LdbExpr {
            val base = if (s[i] == '(') {
                i++
                val e = expr()
                require(s[i++] == ')')
                e
            } else Leaf(num())
            if (i < s.length && s[i] in "=<>") {
                val op = s[i++]
                val x = num()
                val y = if (i < s.length && s[i] == ',') { i++; num() } else null
                return Mod(base, op, x, y)
            }
            return base
        }

        fun num(): Int {
            val st = i
            while (i < s.length && s[i].isDigit()) i++
            require(i > st)
            return s.substring(st, i).toInt()
        }
    }
}
