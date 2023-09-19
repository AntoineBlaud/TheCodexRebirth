# Fairlight Challenge Guide

First, we execute the solution script as follows:

```bash
python3 examples/fairlight/fairlight.py examples/fairlight/fairlight
```

We notice that the script stops. The reason behind this is that we have a symbolic comparison (both operands are symbolic):

- `edx => var_00001 + 0xfffffffffffff548 & 0xffffffffffffffff`
- `eax => in_13 & 0xff`

with `var_00001 == (in_0 & 0xff) * ((in_11 & 0xff) + ((in_9 ^ in_5) & 0xff) & 0xffffffffffffffff) & 0xffffffffffffffff`

...

We provide Z3 with the equation (possibly in a future version the script will do this automatically):

```python
from z3 import *

# Create Z3 variables for in_0, in_5, in_9, and in_11
in_0 = BitVec('in_0', 64)
in_1 = BitVec('in_1', 64)
in_2 = BitVec('in_2', 64)
in_3 = BitVec('in_3', 64)
in_4 = BitVec('in_4', 64)
in_5 = BitVec('in_5', 64)
in_6 = BitVec('in_6', 64)
in_7 = BitVec('in_7', 64)
in_8 = BitVec('in_8', 64)
in_9 = BitVec('in_9', 64)
in_10 = BitVec('in_10', 64)
in_11 = BitVec('in_11', 64)
in_12 = BitVec('in_12', 64)
in_13 = BitVec('in_13', 64)

input = [in_0, in_1, in_2, in_3, in_4, in_5, in_6, in_7, in_8, in_9, in_10, in_11, in_12, in_13]

# Characters must be printable
constraints = [And(in_i >= 48, in_i <= 126) for in_i in input]

# Define the equation
equation = And(
    ((in_0 & 0xff) * ((in_11 & 0xff) + ((in_9 ^ in_5) & 0xff))) + 0xfffffffffffff548 & 0xffffffffffffffff == in_13
)

# Create a Z3 solver and check if the equation is satisfiable
solver = Solver()
solver.add(equation)
solver.add(constraints)

if solver.check() == sat:
    # If the equation is satisfiable, get the model
    model = solver.model()
    # Get the values of in_0, in_5, in_9, in_11, and var_00001 from the model
    for i in input:
        print(chr(model[i].as_long()), end='')
else:
    print('No solution found.')
```

S3's proposed solution:

```
4000020001040t#
```

We update the fairlight.py file to update the password and add hooks for the `rand` function for check 2:

```python
161 register(codex, "4000020001040t#")
162
163 # Register 'rand_callback' for specific addresses for check 1
164 codex.register_callback(0x4008B5, rand_callback)
165 codex.register_callback(0x4008CF, rand_callback)
```

Finally, after execution, we notice that we arrive at a second verification step. We must now add the new constraints and start over.

```
....
0x4009d7   cmp edx, eax
08:57:00  Symbolic register found in edx => var_00003
08:57:00  Symbolic register found in edx => var_00003
08:57:00  Symbolic register found in eax => in_11 & 0xff
08:57:00  edx = 0x1f 
08:57:00  eax = 0x34 
```