# CodexRebirth : A Taint Analysis Approach to Reverse Engineering


## Introduction

The CodexRebirth project seeks to revolutionize the process of reverse engineering by introducing a Taint Analysis approach specifically designed to simplify the unraveling of **obfuscated methods**. This method involves a comprehensive examination of all assembly instructions, tainting every memory address and register in the process. Subsequently, when an instruction relies on a tainted register, memory, or a result derived from these tainted elements, it will execute the operation and update the associated equations. This approach enables the user to easily trace the progression of equations and values, pinpointing the instruction responsible for any value change. Furthermore, the ability to color-code instructions based on their 'taint_id' or 'block similarity' adds an additional layer of clarity to the analysis.

With the assistance of the IDA plugin, program segments are seamlessly mapped into qiling, providing an exact replica of the program in memory. Additionally, the plugin automatically configures registers and memory to their initial values at the start of the function being analyzed, streamlining the reverse engineering process.

*Big Thanks to Markus Gaasedelen (@gaasedelen) because I used his Tenet IDA plugin as a base for mine*

!["IDA plugin"](./doc/imgs/plugin.gif)


## How the tainted analysis works

The tainted analysis is based on the following principles:
- Each instruction is executed and the result is stored in a variable.
- Each variable is first tainted with a unique id.
- When an operation occurs, the result id is the concatenation of the operands ids, and the variable is updated with the result of the instruction.

By following these principles, we can easily track the forward propagation of the taints and the backward propagation of the equations.

![Alt text](doc/imgs/image.png) 

Forwards propagation of the taints is represented by the green cells, and the backward propagation of the equations is represented by the pink cells. **To resume, green cells are the operation that use the current operation result, and pink cells are the operation that are used by the current operation.**

Then backward propagation can be represented as a tree. On same line are represended the operations that takes a RealValue as operand (ex: Imm operand). When a operation occurs on two SymValue, the result is a tree merge of the two operands trees.

![Alt text](doc/imgs/backward.png)



## Installation

**Note: For IDA plugin, you need to have at least python 3.8 installed and IDA must be configured to use it.**

- After python 3.8 is installed, you need run idapyswitch to python 3.8.10, then install setuptools and wheel.
- After that, you can install the CodexRebirth plugin by using python 3.8.10 binary full path (*ex: C:\Users\antoi\AppData\Local\Programs\Python\Python38\python.exe*)

Edit configuration template file **codexrebirth_config.json.template**, set rootfs path to your qiling rootfs path (ex: *C:/your_path/qiling/rootfs*), and rename it to *codexrebirth_config.json*.

Command line installation for the CodexRebirth library:
```bash
python-ida=C:\Users\antoi\AppData\Local\Programs\Python\Python38\python.exe
git clone git@github.com:AntoineBlaud/TheCodexRebirth.git
cd TheCodexRebirth/src
python-ida setup.py sdist bdist_wheel 
python-ida -pip install . 
```
Then copy config file **codexrebirth_config.json** and **src/ida_codexrebirth.py** and to your IDA plugins folder (ex: *C:\Program Files\IDA 7.6\plugins*)


## Basic Usage

- Open the IDA database of the program to analyze.
- Start debugging mode and stop the execution of the program at the beginning of the function to analyze.
- Specify an optional end address for the analysis or modify the default timeout value configured in the CodexRebirth settings
- Open the CodexRebirth context menu and select **Run Symbolic Execution**.
- Wait for the analysis to finish.
- Explore by using mouse wheel while hovering the timeline, or by using previous/next buttons or shortcuts.

## Advanced Usage Insights

- The advanced features of CodexRebirth introduce a powerful capability known as "synchronize variable." This feature enables the synchronization of stack and heap variables with registers, simplifying the task of tracking assembly variables. 

    For instance, consider the following assembly code snippet:

    ```asm
    mov     rax, [rbp+var_1D0]
    mov     eax, [rax]
    ```

    Through CodexRebirth's advanced usage, this code transformation occurs:

    ```asm
    rax_var_1D0 = rax       ; rax = rax_var_1D0
    mov     rax_var_1D0, [rbp+var_1D0]
    mov     eax, [rax_var_1D0]
    ```

    By employing this synchronization feature, CodexRebirth significantly enhances your ability to manage and understand assembly variables, making the reverse engineering process more efficient and intuitive.

- CodexRebirth further enhances the reverse engineering experience by providing a feature that allows users to navigate from a specific instruction to its subsequent or preceding occurrences. This capability facilitates a quick and insightful understanding of an instruction's purpose and functionality.



## Key Usage Considerations

- It's important to note that CodexRebirth currently only implements a partial set of instructions. You are encouraged to contribute by creating an issue or a pull request to expand this list.

- While the analysis of operations is robust, it may not be flawless. For debugging and verification purposes, CodexRebirth provides a valuable parameter: **symbolic_check**. When enabled (set to True), this feature cross-checks the results produced by the Symbolic Engine against those generated by Qiling. If any disparities are detected, the relevant instruction will be highlighted in red within the trace view.

## Performance Insights

The execution speed of CodexRebirth typically ranges between 700 and 1000 instructions per second. However, it's important to note that enabling the **symbolic_check** parameter can significantly impact performance. It's recommended to disable this feature if achieving a precise equation result is not your primary concern.

Furthermore, it's worth considering that the choice between running Windows or Linux binaries can influence the performance, and Qiling's loading time on Windows systems is notably slower, which will extend the analysis initiation process.

*These performance metrics were obtained using Python 3.8 on a CPU Ryzen 5900HX with a clock speed ranging from 3.3GHz to 4.6GHz.*

## Tree View
**The tree representation has been removed from the plugin because generating it was too slow.** Previously it worked like this:
- Operation between RealValue and anytype of value (SymValue or RealValue) are string merged into same node
- Operation between SymValues are tree merged. 
- Even by limiting the number of tree copy, the performance was too slow.

## Maybe Future Work

- Print the equation of the current instruction in the output window.


## What's Next ? 

- Use Dynamic Binary Instrumentation to improve the performance of the tracing engine.
- Rewrite the backend in C++ to improve the performance of the plugin.
- Discover a way to easy implement new instructions, or find a project that already implement a lot of instructions and that is compatible with our operation model.
- Create new views to display : 
    - the taint tree
    - the call graph as directory/subdirectory with sorted functions, and the ability to group call sequence
    - the block graph like the call graph
    - memory view with segment choice, and previsualisation of the memory read and write


