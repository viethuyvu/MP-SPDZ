#Core MPC operations: arithmetic-to-boolean (A2B) conversion.
#Converts an array of secret integers (sint) to an array of secret bits (sbitvec).

@export
def a2b(x, res):
    print_ln('x=%s', x.reveal())
    res[:] = sbitvec(x, length=16)
    print_ln('res=%s', x.reveal())

a2b(sint(size=10), sbitvec.get_type(16).Array(10))
