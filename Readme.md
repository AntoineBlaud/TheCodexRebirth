# CodexRebirth Project

The CodexRebirth project aims to simplify the reverse engineering of obfuscated methods using a Taint Analysis approach. It will analyze all assembly instructions and, when one depends on a tainted register or memory, or on a result derived from one of these tainted values, it will process the operation and update the relevant equations.

**If you are looking at this project out of curiosity, I suggest trying to understand the algorithm protected by Tigress in the `examples/tigress/src-tigress-protected` directory, or even better, attempting to do so from the compiled version. The purpose of this project is precisely to combat this kind of protection.**

CodexRebirth has two modes of operation:

- Command line
- IDA Plugin (Not yet available)

Using the IDA plugin is recommended as it greatly facilitates the analysis setup and allows for more efficient result examination. It helps navigate effectively to trace the path.

## INSTALLATION

```bash
git clone git@github.com:AntoineBlaud/TheCodexRebirth.git
cd TheCodexRebirth/src
python3 setup.py sdist bdist_wheel 
pip3 install . 
```

## USAGE

Check the examples in this order:

- examples/fairlight
- examples/tigress/siphash24
- examples/tigress/mix2, examples of variable destruction
- examples/tigress/indirect_load, an example of indirect variable loading
- examples/tigress/sample14, long string input of size 48, function is not obfuscated

## Key Points for Usage

- Note that only a portion of the instructions is implemented; you can create an issue or a pull request to add more.

- The analysis of operations may not be perfect; therefore, for debugging and verification, CodexRebirth provides two parameters:
  - `strict_symbolic_check` -> If set to True, the program will stop as soon as an error is detected, allowing for investigation.
  - `symbolic_check` -> Removes tainted values that do not correspond to memory values (which may cause certain details to be missed).

- Having `symbolic_check` disabled allow to speed up execution to 3000 instructions per second instead of 500

- For memory strings, you should use `taint_memory` with a byte step size of 1 or `sizeof(int)` depending on their usage. If the string is read by moving 4 or 8 bytes at a time, and you set the memory step size to 1, it will not work correctly.

- If you find `addrof` in your results, it means that the script contains operations similar to those in the `indirect_load.c` file.

