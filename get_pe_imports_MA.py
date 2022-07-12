from write_csv_data_MA import write_csv_data
import sys
import pefile

pe_imp_fields = ["Executable", "Library", "Imported function"]
FIELD_EXENAME = 0
FIELD_LIBNAME = 1
FIELD_IMPORT = 2

def generate_pe_import_list(arg_fname_list):
    
    data = list()
    pe = 0

    for fname in arg_fname_list:
        
        try:
            pe = pefile.PE(fname)
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                print("Processing imported functions: " + fname)
                
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        
                        if imp.name != None:
                            data.append({
                                pe_imp_fields[FIELD_EXENAME]: fname,
                                pe_imp_fields[FIELD_LIBNAME]: entry.dll.decode("utf-8"),
                                pe_imp_fields[FIELD_IMPORT]: imp.name.decode("utf-8")
                            })
                        
                        else:
                            data.append({
                                pe_imp_fields[FIELD_EXENAME]: fname,
                                pe_imp_fields[FIELD_LIBNAME]: entry.dll.decode("utf-8"),
                                pe_imp_fields[FIELD_IMPORT]: str(imp.ordinal)
                            })
            
            else:
                print("Have no imported functions: " + fname)
        
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return data

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
        
    fname_set = set()
    for i in range(2, argc):
        fname_set.add(sys.argv[i])
        
    data = generate_pe_import_list(fname_set)
    write_csv_data(data, pe_imp_fields, sys.argv[1])
        
    print("Imported functions of files provided written to " + sys.argv[1])

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
