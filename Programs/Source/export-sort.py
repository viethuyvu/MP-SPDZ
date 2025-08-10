#Core MPC operations:  sorting of a secret array (sint.Array).
#orts an array of 1000 secret integers.
@export
def sort(x):
    print_ln('x=%s', x.reveal())
    res = x.sort()
    print_ln('res=%s', x.reveal())

sort(sint.Array(1000))
