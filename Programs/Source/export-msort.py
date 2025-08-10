#Core MPC operations: sorting of a secret matrix (sint.Matrix) based on a key index.
#Sorts a 500x2 matrix of secret integers using the first column as the key (specified by key_indices).
@export
def sort(x, key_indices):
    print_ln('x=%s', x.reveal())
    print_ln('key_indices=%s', key_indices)
    res = x.sort(key_indices=key_indices)
    print_ln('res=%s', x.reveal())

sort(sint.Matrix(500, 2), regint(0, size=1))
