/* wiresharkdissect.h
 *
 * wiresharkdissect.dll Library
 * Exporting a simple function to enable usage of the dissectors from C# on Windows.
 * 
 * Author: Kam Reypour
 */

#ifndef __WIRESHARKDISSECTORS_H__
#define __WIRESHARKDISSECTORS_H__

#include "ws_symbol_export.h"

WS_DLL_PUBLIC
int dissect(const char *input, int input_len, char *output, int output_len);

#endif /* __WIRESHARKDISSECTORS_H__ */
