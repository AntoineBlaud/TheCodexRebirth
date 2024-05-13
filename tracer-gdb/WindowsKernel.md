# gbd-tools Windows Kernel (without IDA)

## How to Use

### Disable Hypervisor and Reboot

If you're encountering issues with VMware breakpoints due to Hyper-V being enabled, you'll need to disable the hypervisor and reboot your system:

```bash
bcdedit /set hypervisorlaunchtype off
```

Please note that VMware breakpoints are not supported when Hyper-V is enabled.

### Configuring Windows Machine

Before proceeding, ensure you have a Windows machine with VMware Workstation Pro installed. Follow these steps to configure your Windows machine to allow the kernel debugger to connect to the VM:

1. Enable debug mode:

```bash
bcdedit /debug on
bcdedit /set TESTSIGNING ON 
bcdedit /dbgsettings net hostip:<hostip> port:50000
```

2. Enable debugging in the VM settings by editing the VMX file and adding the following lines:

```bash
debugStub.listen.guest64 = "TRUE"
debugStub.listen.guest32 = "TRUE"
debugStub.listen.guest64.remote = "TRUE"
debugStub.listen.guest32.remote = "TRUE"
debugStub.hideBreakpoints = "TRUE" # Optional: If set, ensure max_bp matches the number of hardware breakpoints available
```

### Connecting Windbg to the VM

1. Connect Windbg of your Host machine to the VM:

```bash
windbg -k net:port=50000,key=<hostip> # Or use the GUI
```

2. Reload the symbols:

```bash
.reload /f
```
3. Find the address of the function you want to set a breakpoint on:


### Connecting gdb to the VM

Ensure you have gdb installed along with pwndbg. Follow these steps to connect gdb to the VM:

1. Open gdb:

```bash
gdb
```

2. Connect gdb to the VM:

```bash
target remote <vmip>:<defaultport> # Default port is 8864 for 64-bit architecture and 8832 for 32-bit architecture
```
3 . Set a breakpoint at the desired function:

```bash
b <function_address>
```
4. Launch the program:

```bash
source step_tracer.py
```

These steps should enable you to effectively utilize gbd-tools for Windows Kernel debugging without IDA.
