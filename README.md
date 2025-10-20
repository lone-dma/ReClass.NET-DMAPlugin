# ReClass.NET-DMAPlugin
A plugin that integrates with the [MemProcFS (PCILeech)](https://github.com/ufrisk/MemProcFS) project to allow ReClass.NET to function over a FPGA device.

## Notes on this fork
- Updated for MemProcFS v5.15

## Usage

* Copy `VmmPlugin.dll` into the ReClass.NET\Plugins directory
* Copy the other native files into the CWD (Current Working Directory, usually where ReClass.NET is stored).
* Open Reclass.NET, go to File -> Plugins
* Switch to the Native Helper tab and change the Functions Provider from Default to PciLeechPlugin
