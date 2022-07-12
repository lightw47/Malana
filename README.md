
# Malana
**Malana** is a collection of scripts aimed to help me do static analysis of files, usually malware.

## Dependencies
Malana depends on
- `pefile`
- `ssdeep`
- `vt`

`pefile` can be easily installed via pip: `pip install pefile`

To install `ssdeep`, you might have to install some libraries before installing the package itself. On Linux systems,  you just need to install `libfuzzy` before `pip install ssdeep`. On Windows, download [ssdeep Python wrapper for Windows](https://github.com/MacDue/ssdeep-windows-32_64), then run `setup.py install`.

`vt` is also easily installev via pip: `pip install vt-py`

## How to use
Malana currently consists of the following "core" scripts:
- `get_hashes_MA.py`
- `get_pe_exports_MA.py`
- `get_pe_imports_MA.py`
- `vt_scout_MA.py`

All of them share the same usage:

`<script name> [-h] [-o csvoutput] filename [filename ...]`

Just invoke the script name, provide at least one file name and the script outputs the desired information in Python's dictionary format. If needed, you can use the `-o csvoutput` option to save the data in CSV format.

### Using VirusTotal Api
Some scripts use VirusTotal API (currently, only `vt_scout_MA.py` needs it). To use them, update the file `api_keys_MA.py` and replace the dummy API keys with your own keys.
