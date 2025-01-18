<p align="center">
    <h1>Relocatable</h1>
</p>
<p align="center">
    <a href="https://github.com/tijme/relocatable/blob/master/LICENSE.md">
        <img src="https://img.shields.io/badge/License-MPL%20V2.0-527c50?style=for-the-badge&labelColor=2b4e34" />
    </a> &nbsp;
    <a href="https://github.com/tijme/relocatable/releases">
        <img src="https://img.shields.io/github/v/release/tijme/relocatable?style=for-the-badge&labelColor=2b4e34&color=527c50" />
    </a> &nbsp;
    <a href="https://github.com/tijme/relocatable/actions">
        <img src="https://img.shields.io/github/actions/workflow/status/tijme/relocatable/compile.yml?style=for-the-badge&labelColor=2b4e34&color=527c50" />
    </a>
</p>
<p align="center">
    <b>Boilerplate to develop raw and truly Position Independent Code (PIC).</b>
    <br/>
    <sup>Built with ♥ by <a href="https://x.com/tijme">Tijme Gommers</a> – Buy me a coffee via <a href="https://www.paypal.me/tijmegommers">PayPal</a>.</sup>
    <br/>
</p>
<p align="center">
    <a href="#abstract">Abstract</a>
    •
    <a href="#getting-started">Getting started</a>
    •
    <a href="#issues--requests">Issues & requests</a>
    •
    <a href="#license--copyright">License & copyright</a>
</p>
<hr>

## Abstract

Sometimes you want to write Position Independent Code (PIC) in plain C (well, at least I do). Relocatable helps you do so. It allows you to write C-code that will be directly compiled into raw shellcode, which can be loaded into any process without the need for tools such as Donut or sRDI. An advantage is that the output size of the shellcode is extremely small (almost no overhead), and the shellcode remains simple.

## Getting started

Clone this repository first. Install the dependencies, then [review the code](https://github.com/tijme/relocatable/blob/master/.github/laughing.gif).

**Dependencies**

* [MinGW](https://formulae.brew.sh/formula/mingw-w64)

**Modify the code**

Adjust the code in `./src/main.c` to your needs. The included example code pops a message box.

**Compiling**

    make

**Usage**

Load `./dst/relocatable.x64.bin` using your shellcode loader (technique) of choice. You can also convert it to a c-code array using `xxd`.

    xxd -i dst/relocatable.x64.bin

This outputs about a 1000 bytes. An example is included below.

    unsigned char dst_relocatable_x64_bin[] = {
      0x55, 0x48, 0x89, 0xe5, 0xe8, 0x55, 0x03, 0x00, 0x00, 0x90, 0x5d, 0xc3,
      0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x10, 0xc7, 0x45, 0xfc, 0x60,
      0x00, 0x00, 0x00, 0x8b, 0x45, 0xfc, 0x65, 0x48, 0x8b, 0x00, 0x48, 0x8
      -- snip --

## Issues & requests

Issues or new feature requests can be reported via the [issue tracker](https://github.com/tijme/relocatable/issues). Please make sure your issue or feature has not yet been reported by anyone else before submitting a new one.

## License & copyright

Copyright (c) 2025 Tijme Gommers. Relocatable is released under the GNU General Public License, version 2.0. View [LICENSE.md](https://github.com/tijme/relocatable/blob/master/LICENSE.md) for the full license. Relocatable was inspired by [ShellcodeStdio](https://github.com/jackullrich/ShellcodeStdio/tree/master), which is also licenced under the [GNU General Public License, version 2.0](https://github.com/zyantific/zydis/blob/master/LICENSE).