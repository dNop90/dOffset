# dOffset
dOffset is a plugin designed for IDA Pro and Cheat Engine, offering a convenient way to obtain the offset of the current module. This enables users to navigate to specific addresses in other reverse engineering software easily. It is beneficial when performing static analysis of a file while simultaneously debugging with multiple tools, including IDA Pro, Cheat Engine, x64dbg, and others.


## IDA Pro
IDA Pro version 7.4+ and Python 3

### Features
- Jump to specific offset
- Get offset
- Get module name and offset

### Installation
Place the `dOffset.py` file in the `plugins` folder where your IDA Pro is installed.

### Usage
Right-click on any line in the IDA view, and you should see the `dOffset` option. Select either `Get offset` or `Get module name + offset`, and the result will be copied to your clipboard.<br>
To jump to a specific offset, navigate to the `Jump` menu, then select `dOffset` and `Jump to offset`. Enter the desired offset.

### Screenshots
![IDA1](/images/ida1.png)

![IDA1](/images/ida2.png)


## Cheat Engine

### Features
- Get offset (Disassembler and Hexadecimal view)
- Get module name and offset (Disassembler and Hexadecimal view)

### Installation
Place the `dOffset.lua` file in the `autorun` folder where your Cheat Engine is installed.

### Usage
Right-click on any line in the Disassembler or on any hex in the Hexadecimal viewer, then you should see the `dOffset` option. Select either `Get offset` or `Get module name + offset`, and the result will be copied to your clipboard. If the current address is not part of any module, you will not be able to get the offset.

### Screenshots
![CE1](/images/ce1.png)

![CE2](/images/ce2.png)

