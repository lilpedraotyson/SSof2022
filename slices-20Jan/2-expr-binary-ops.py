a=b() a -> tainted (a,b)
c=s("ola",a) c -> sanitizado
f=e(c+"oi"+d+"hi",a) (e, b)[s] (e, d) ()

A
source = a,d
sink = d,e

B
source = b
sinks = a,e
# tip: expressions might involve binary operations with arguments of different levels, arguments of sanitizers and sinks can also be expressions, and sanitized and unsanitized data can reach sinks simultaneously

