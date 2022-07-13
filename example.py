import malana

# build your data set
data = set()
data.add("c:\\windows\\notepad.exe")
data.add("c:\\windows\\regedit.exe")
data.add("c:\\windows\\write.exe")

# read imported functions from files in the data set
imports = malana.get_pe_imports(data)

# get all executables importing LoadLibraryW
rule = {"import": "LoadLibraryW"}
load_library_pe = malana.search(imports, rule, "filename")

# scout VT looking for PE files that match the rule above
result = malana.vt_scout(load_library_pe)

# export results to a CSV file 
malana.write_csv_data(result, malana.vt_analysis_fields, "output.csv")