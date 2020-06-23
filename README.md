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
   int output_len,
   gboolean detailed_json,
   int pkt_size,
   int encap_type,
   guint64 timestamp
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

**detailed_json**

The results can be either a summary text or a detailed json object that is controlled by this parameter.

**pkt_size**

This is the actual size of the packet which normally found from the capture file. If unknow, just set to the same value as input_len.

**encap_type**

The type of encapsulation that are found in wtap.h in Wireshark. For example, for ethernet set to 1, which is WTAP_ENCAP_ETHERNET.

**timestamp**

Nano seconds since epoch time of capture. If unknonw, set to 0.

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
        static extern int dissect(
            byte[] input,
            int input_len,
            [MarshalAs(UnmanagedType.LPUTF8Str)] StringBuilder output,
            int output_len,
            bool detailed_json,
            int pkt_size,
            int encap_type,
            UInt64 time
        );

        static void Main(string[] args)
        {
            int output_len = 4096;
            StringBuilder output = new StringBuilder(output_len);
            byte[] input = { 
                0xa2, 0x00, 0x82, 0x03, 0x07, 0x01, 0x44, 0xa8,
                0x42, 0x18, 0x83, 0x4a, 0x08, 0x00, 0x45, 0x00,
                0x04, 0xde, 0xb2, 0x89, 0x00, 0x00, 0x80, 0x11,
                0x2f, 0x09, 0x0a, 0xe7, 0x7a, 0x67, 0x0a, 0x89,
                0xc4, 0xa5, 0x0d, 0x3d, 0xef, 0x98, 0x04, 0xca,
                0x59, 0xfa, 0x07, 0x05, 0x04, 0xd3, 0x00, 0xc8,
                0x00, 0x0c, 0x00, 0x01, 0x08, 0xde, 0xb9, 0xfc,
                0xc7, 0xd1, 0xb9, 0xfc, 0xc7, 0xb3, 0x17, 0x03,
                0x03, 0x06, 0x5c, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0b, 0x45, 0x9b, 0x7b, 0x0c, 0xed, 0x7f, 0x0f,
                0x25, 0x45, 0xd2, 0xf8, 0xee, 0x25, 0x35, 0xfa,
                0x7d, 0x35, 0x73, 0xd1, 0xac, 0x18, 0xe6, 0xbc,
                0x54, 0xed, 0xef, 0xb1, 0x50, 0xc0, 0x5f, 0xc0,
                0x6f, 0xe5, 0x52, 0xa5, 0xdd, 0x9b, 0x8c, 0x57,
                0x5a, 0xeb, 0x23, 0x0c, 0x8a, 0x3a, 0x5c, 0xaa,
                0xa8, 0x3e, 0xc8, 0x3a, 0x88, 0x6b, 0xb5, 0x15
            };

            int err = dissect(
                input,
                input.Length,
                output,
                output_len,
                true,
                1260,
                1,
                0
            );
            if (err == 0)
            {
                Console.OutputEncoding = System.Text.Encoding.Unicode;
                Console.WriteLine(output.ToString());
            }
        }
    }
}
```