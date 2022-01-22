a=""; a -> untainted
a=b(); a -> tainted
c=a; c -> tainted
d=c; (d,c) (d,b) d -> tainted
e(d);  (e,c) (e,b) e -> tainted
c="";

# tip: assignments propagate taintedness, and the order in which they are performed matters
