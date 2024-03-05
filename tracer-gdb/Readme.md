# gdb-tools (without IDA)

This collection of tools is designed to facilitate debugging with GDB in scenarios where IDA may not be suitable or accessible. For instance, when dealing with debugging issues on Android or encountering mitigations that prevent traditional debugging approaches, these tools can be invaluable.

## Why Use These Tools?

IDA, while powerful, may not always be the optimal solution. Certain debuggee processes, particularly on platforms like Android, might have protections in place that hinder IDA's effectiveness. These tools provide an alternative method for debugging in such situations, offering flexibility and reliability.

## How to Use

Follow the step-by-step tutorial for android debugging provided in this [gist](https://gist.github.com/sekkr1/6adf2741ed3bc741b53ab276d35fd047).

For users of Windows Subsystem for Linux (WSL), install the MSI from [this repository](https://github.com/dorssel/usbipd-win/actions/runs/7813976713), and refer to the Microsoft tutorial on connecting USB devices in WSL [here](https://learn.microsoft.com/en-us/windows/wsl/connect-usb).

### Execution Commands

**Linux:**
```bash
adb shell 'am start -D -n 'com.supercell.clashofclans/com.supercell.titan.GameApp' -a android.intent.action.MAIN -c android.intent.category.LAUNCHER' && PID=$(adb shell ps | grep com.supercell.clashofclans | grep -v : | awk '{print $2}'); CMD="/data/local/tmp/gdbserver_arm --attach localhost:1339 ${PID}"; adb shell su -c "${CMD}"
```

**Windows:**
```powershell
adb shell 'am start -D -n com.supercell.clashofclans/com.supercell.titan.GameApp -a android.intent.action.MAIN -c android.intent.category.LAUNCHER'; $PID_A = $((adb shell ps) -replace '\s+', ' ' | Select-String 'com.supercell.clashofclans' | ForEach-Object { $_.ToString().Split(' ')[1] }); $CMD = "/data/local/tmp/gdbserver_arm --attach localhost:1339 $PID_A"; adb shell su -c $CMD
```

Then launch GDB with the following command:
```bash
gdb-multiarch
```

### Additional Tools

- **Ultimap:** Execute `source .ultimap.py` and `ultimap` to activate the Ultimap feature.
- **GDB Tracer:** Run `source gbd-tracer.py` and `tracer` to utilize the GDB Tracer tool. You can adjust settings within the `gbd-tracer.py` file as needed.

### Performance Tip

For enhanced performance, set `solib-absolute-prefix` to `/root/dbgtmp/` . This step is crucial for optimal functioning.

These tools provide a versatile and reliable debugging solution when traditional methods fall short. Feel free to customize and extend them to suit your specific debugging needs.