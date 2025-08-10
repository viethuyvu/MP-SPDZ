#Core MPC operations: boolean-to-arithmetic (B2A) conversion.
#Converts an array of secret bits (sbitvec) back to an array of secret integers (sint).
@export
def b2a(res, x):
    print_ln('x=%s', x.reveal())
    res[:] = sint(x[:])
    print_ln('res=%s', x.reveal())

b2a(sint.Array(size=10), sbitvec.get_type(16).Array(10))
