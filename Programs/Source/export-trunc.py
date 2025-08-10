#Core MPC operations:  truncation (rounding) of secret integers.
#Rounds a secret integer (sint) to a fixed-point representation with 32 bits, keeping 2 bits after the decimal point.
@export
def trunc_pr(x):
    print_ln('x=%s', x.reveal())
    res = x.round(32, 2)
    print_ln('res=%s', res.reveal())
    return res

trunc_pr(sint(0, size=1000))
