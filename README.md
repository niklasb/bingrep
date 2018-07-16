# bingrep

A small utility to grep for pointers and binary data in memory dumps or live process memory.

## Usage

```
Exactly one of -f or -p has to be specified.

Usage:
 1) bingrep -f <filename>       [pattern]
 2) bingrep -p <pid> [-i <num>] [pattern]

Pattern can be one of:
 -s <from addr> -e <to addr> [-w <pointer size, 4 or 8 (default)>]
 -b <hex>
 -a <ascii>

For type 2), -i specifies the number of dereferences before
trying to match the pattern
```

## Examples:

```
$ ./bingrep -p $(pgrep -f firefox|tail -n1) -s 0x6314a7bc7220 -e 0x6314a7bc7220 -i 1 2>/dev/null
00006314c0389360
```
