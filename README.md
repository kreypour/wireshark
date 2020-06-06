# General Information
This fork of Wireshark adds a single dll file, wiresharkdissect.dll, to enable consumption of the dissectors from C# on Windows. The goal is to make minimal changes to the code so when the dissectors are updated, merging the main branch would run into no conflicts.

# Changes
The code added to the project is within a single .c, corresponding .h, and a NSIS installer file as follows:
```
/wiresharkdissect.c
/wiresharkdissect.h
/wiresharkdissect.nsi
```

Also, the following cmake file has been modified for building the dll.
```
/CMakeLists.txt
```

# Build
Building the project follows the exact same steps provided in the main Wireshark developer doc for win32.

https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html#ChWin32Build

Creating the installer file will require installation of NSIS, and EnvVar plugin for NSIS.
After installation of NSIS, download and install EnvVar plugin by extracting the Zip and copying the DLLs to your NSIS\Plugins folder. Then copy the following files to where the binary folder of your build (where wiresharkdissect.dll is placed). Note that if you don't already have vcruntime140.dll, you need to download it from https://www.microsoft.com/en-us/download/details.aspx?id=52685.

```
/wiresharkdissect.nsi
vcruntime140.dll
```
Now you can run MakeNSISW.exe, open wiresharkdissect.nsi to compile the installer, wiresharkdissect.exe. The installer will copy all the necessary DLLs to the directory of your choosing and add a system environment variable, WIRESHARK_DISSECT_DIR, containing the installation folder.

# Usage
The exported function, dissect, takes 4 parameters and returns an error code as follows.

## Syntax
```
int dissect(
    const char *input,
    int input_len,
    char *output,
    int output_len
);
```

## Parameters

**input**

A byte buffer containing the frame you want to dissect.

**input_len**

The size of the byte buffer.

**output**

An allocated memory buffer to receive the dissected frame as a JSON object.

**output_len**

The size of allocation of output.

## Return Value

Return value is an int error code. The output buffer should only be used upon getting return value of 0, which is success. One special return value is 122 (ERROR_INSUFFICIENT_BUFFER), which means the output buffer provided is too small, so a retry with a bigger buffer should succeed.

## Example

```
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace WiresharkdissectTest
{
    class Program
    {
        [DllImport(@"\path\to\wiresharkdissect.dll")]
        static extern int dissect(byte[] input, int input_len, StringBuilder output, int output_len);

        static void Main(string[] args)
        {
            int output_len = 4096;
            StringBuilder output = new StringBuilder(output_len);
            byte[] input = { 
                0x00, 0x00, 0x5E, 0x00, 0x01, 0x02, 0x94, 0x57, 0xA5, 0xED, 0x9A, 0x0B, 0x08, 0x00, 0x45,
                0x00, 0x00, 0x3C, 0xC0, 0xAC, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x0A, 0x89, 0xC4, 0xF4,
                0x0A, 0xE1, 0x69, 0x2E, 0x08, 0x00, 0x24, 0x88, 0x00, 0x01, 0x28, 0xD3, 0x61, 0x62, 0x63,
                0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
                0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69
            };

            int err = dissect(input, input.Length, output, output_len);
            if (err == 0)
            {
                Console.WriteLine(output.ToString());
            }
        }
    }
}
```