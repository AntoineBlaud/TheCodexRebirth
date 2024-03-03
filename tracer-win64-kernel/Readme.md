 
# Extension for WinDbg - Trace Utility

## Important:
- Ensure capstone.dll is in the same folder as WinDbgStalker.dll.
- Before loading the extension, execute the .reload command.
- Speed execution is around 200 instructions per second. Better than human speed :)
- X64/Release build is available (see Release folder).

## Usage:
1. Load the extension using the following command:
   .load C:\Path\To\WinDbgStalker.dll

2. Export the function definitions of the module to trace using Tenet plugin,
   or use the ExportFunctionDefinitions.py script provided in the repository.
    The script will generate a file containing the function definitions of the module.
    Example: C:\Path\To\AntiCheatDriverExport.txt
    Only 32 first functions will be selected for tracing.

3. Attach a module for tracing:
   !WinDbgStalker.AttachModule module_name function_def_file_path
   Example: !WinDbgStalker.AttachModule AnticheatDriver C:\Path\To\AntiCheatDriverExport.txt

4. Run the trace:
   !WinDbgStalker.Run max_running_time max_bp_hit_count
   Example: !WinDbgStalker.Run 60 10  // Run for 60 seconds with a maximum of 10 breakpoint hit for each function

5. Unload the extension when done:
   .unload WinDbgStalker

Example Workflow:
1. .reload
2. .load C:\Path\To\WinDbgStalker.dll
3. !WinDbgStalker.AttachModule AnticheatDriver C:\Path\To\AntiCheatDriverExport.txt
4. !WinDbgStalker.Run 60 10
5. .unload WinDbgStalker

## Commands:
- !WinDbgStalker.Help
   Display this help message.

- !WinDbgStalker.QueryTracerPerformances
   Query and display performance statistics of the tracer.

- !WinDbgStalker.Flush
   Flush the trace buffer.

## Note:
- Ensure only one space between arguments.
- Remove all breakpoints before running the extension.
- Maximum 32 breakpoints can be set (win32 limitation).

## Coverage Tutorial:

As previously mentioned, it's important to note that only 32 breakpoints can be set simultaneously. If your objective is to reverse engineer a Kernel driver, employing the export function script is highly recommended. This script efficiently organizes functions based on their size and sub-coverage.

Here's a step-by-step approach:

1. Utilize the export function script to organize functions in the export file by size and sub-coverage.
2. Initiate the tracer and let it run for 100 seconds.
3. Remove the first 32 functions from the export file.
4. Restart the tracer and run it again for another 100 seconds.
5. Repeat this process iteratively until you achieve comprehensive coverage.

**It's essential to keep in mind that the trace remains clean only when the flush function is called. This ensures accuracy and reliability throughout the reverse engineering process.**


You can try the extension with the following project:
https://github.com/donnaskiez/ac


