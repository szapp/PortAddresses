# PortAddresses

Python command-line functions for IDA (The Interactive Disassembler) to aid in finding identical symbols and their
addresses across different builds of an executable

## Usage

Import the plugin into IDA, e.g. by placing the folder `portaddr` into the subdirectory `python` in the IDA install
directory.
Import the package from the IDAPython command-line with
```python
>>> import portaddr as pa
```
Run the functions from command-line.

### Example usage

The functions are useful, when porting a set of addresses from one build executable to another.

Find the symbol of a specific address in memory in executable A.
```python
>>> pa.find.name(0x7A2F44)
Info(name='_printf', uid='_printf', addr='0x7A2F44', offset='8')
```
(Using `pa.find.encode` instead, copies "\_printf+8" into the clipboard for convenience)

Find the corresponding address in memory in executable B.
```python
>>> pa.find.decode('_printf+8', clipboard=False)
_printf = 8007492; //0x7A2F44
```

## Dependencies
- IDA with the IDAPython plugin (Python 2.7.18), specifically the Python package `idaapi`
- pyperclip (1.8.2)
