# CodexRebirth Project

The CodexRebirth project aims to simplify the reverse engineering of obfuscated methods using a Taint Analysis approach. It will analyze all assembly instructions and, when one depends on a tainted register or memory, or on a result derived from one of these tainted values, it will process the operation and update the relevant equations.

With the IDA plugin, the program segments are automatically mapped in qiling, so you will have a exact copy of the program in memory. The plugin will then automatically set the registers and memory to the values of the registers and memory at the beginning of the function to analyze. It will then execute the function and analyze the instructions one by one. After that you can navigate through the results. 


![ida_plugin](./doc/imgs/ida_plugin.gif)

**If you are looking at this project out of curiosity, I suggest trying to understand the algorithm protected by Tigress in the `examples/tigress/src-tigress-protected` directory, or even better, attempting to do so from the compiled version. The purpose of this project is precisely to combat this kind of protection.**

CodexRebirth has two modes of operation:

- Command line
- IDA Plugin 

*Big Thanks to Markus Gaasedelen (@gaasedelen) because I used his Tenet IDA plugin as a base for mine*

Using the IDA plugin is recommended as it greatly facilitates the analysis setup and allows for more efficient result examination. It helps navigate effectively to trace the path.

## INSTALLATION

**Note: For IDA plugin, you need to have at least python 3.8 installed and IDA must be configured to use it.**

- After python 3.8 is installed, you need run idapyswitch to python 3.8.10, then install setuptools and wheel.
- After that, you can install the CodexRebirth plugin by using python 3.8.10 binary full path (ex: *C:\Users\antoi\AppData\Local\Programs\Python\Python38\python.exe*)


Command line installation for the CodexRebirth library:
```bash
git clone git@github.com:AntoineBlaud/TheCodexRebirth.git
cd TheCodexRebirth/src
python3 setup.py sdist bdist_wheel 
pip3 install . 
```



## USAGE (Command Line)


Check the examples in this order:

- examples/fairlight
- examples/tigress/siphash24
- examples/tigress/mix2, examples of variable destruction
- examples/tigress/indirect_load, an example of indirect variable loading
- examples/tigress/sample14, long string input of size 48, function is not obfuscated


## USAGE (IDA Plugin)

- Open the IDA database of the program to analyze.
- Write a controller script like the one in `examples/ida_plugin/controller_template.py` (you can copy it and modify it to your needs).
- Start debugging mode and stop the execution of the program at the beginning of the function to analyze.
- Open the output window (View -> Output Window) or press ALT+0.
- Open the IDA plugin (File -> Script File... -> ida_codexrebirth.py)
- Follow the instructions in the plugin window.
- Once the analysis is complete, the plugin will display the results in the output window.
- You can navigate through the results using mouse scroll while hovering the timeline one the right side of the disassembly window.
- Press `CTRL+leftclick` to select a small portion of the timeline to analyze.


## Key Points for Usage

- Note that only a portion of the instructions is implemented; you can create an issue or a pull request to add more.

- The analysis of operations may not be perfect; therefore, for debugging and verification, CodexRebirth provides two parameters:
  - `strict_symbolic_check` -> If set to True, the program will stop as soon as an error is detected, allowing for investigation.
  - `symbolic_check` -> Removes tainted values that do not correspond to memory values (which may cause certain details to be missed).

- Having `symbolic_check` disabled allow to speed up execution to 2500 instructions per second instead of 340 (metrics obtained with Python 3.11 and a CPU Ryzen 5900HX 3.3GHz-4.6GHz)

- The CodexRebirth library is slower when running in IDA. According to the tests, it's **5 times slower** than in my wsl instance. 

- For memory strings, you should use `taint_memory` with a byte step size of 1 or `sizeof(int)` depending on their usage. If the string is read by moving 4 or 8 bytes at a time, and you set the memory step size to 1, it will not work correctly. Have a look on the `examples/ida_plugin/controller_template.py` function `taint_memory_with_string` for a good starting point.

- If you find `addrof` in your results, it means that the script contains operations similar to those in the `indirect_load.c` file.

