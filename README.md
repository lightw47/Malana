# Malana
**Malana** is a Python module aimed to help me do static analysis of files, usually malware.

Malana was tested with Python version **3.7.3**.

## Dependencies
Malana depends on
- `pefile`
- `ssdeep`
- `vt`

`pefile` can be easily installed via pip: `pip install pefile`

To install `ssdeep`, you need to install some libraries before installing the module itself. On Linux systems, you may need to install `libfuzzy-dev` before `pip install ssdeep`. On Windows, download [ssdeep Python wrapper for Windows](https://github.com/MacDue/ssdeep-windows-32_64), then run `setup.py install`.

`vt` is also easily installed via pip: `pip install vt-py`

## How to use
Malana currently consists of the following "core" scripts, indicated by the `_MA` suffix:
- `get_hashes_MA.py`
- `get_pe_exports_MA.py`
- `get_pe_imports_MA.py`
- `vt_scout_MA.py`
- `vt_submit_MA.py`

All of them share the same usage:

	<script name> [-h] [-o csvoutput] filename [filename ...]

Just invoke the script name, provide at least one file name and the script outputs the desired information in Python's dictionary format. If needed, you can use option `-o csvoutput` to save the output in CSV format.

### Using VirusTotal Api
Some scripts use VirusTotal API. To use them, update the file `api_keys.py` and replace the dummy API keys with your own keys.

### Advanced usage
The `search` function allows the use of other functions in a modular fashion. File `example.py` shows how this can be achieved.
