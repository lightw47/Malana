import sys
import pefile
import csv

pe_imp_fields = ["Executable", "Library", "Imported function"]

def generate_pe_import_list(arg_fname_list):
    list_dict = list()
    pe = 0

    for fname in arg_fname_list:
        try:
            pe = pefile.PE(fname)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                print("Processing imported functions: " + fname)
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name != None:
                            list_dict.append({pe_imp_fields[0]: fname, pe_imp_fields[1]: entry.dll.decode("utf-8"), pe_imp_fields[2]: imp.name.decode("utf-8")})
                        else:
                            list_dict.append({pe_imp_fields[0]: fname, pe_imp_fields[1]: entry.dll.decode("utf-8"), pe_imp_fields[2]: str(imp.ordinal)})
            else:
                print("Have no imported functions: " + fname)
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return list_dict

def main():
    print("LightW's \"Get PE Imports\"")
    print()

    argc = len(sys.argv)

    if argc == 1:
        print("Usage:")
        print("lw_get_pe_imports.py <outfile (csv)> <filename> [filename] [filename] ...")
        exit()

    if argc == 2:
        print("Please, provide at least one file")
        exit()
        
    fname_list = list()
    for i in range(2, argc):
        fname_list.append(sys.argv[i])
        
    with open(sys.argv[1], "w") as outfile:    
        list_dict = generate_pe_import_list(fname_list)
        csvw = csv.DictWriter(outfile, fieldnames = pe_imp_fields)
        csvw.writeheader()
        csvw.writerows(list_dict)
        
        print("Imported functions of files provided written to " + sys.argv[1])

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
