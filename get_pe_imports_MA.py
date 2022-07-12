from write_console_output_MA import write_console_output
from write_csv_data_MA import write_csv_data
import argparse
import pefile

pe_imp_fields = ["Executable", "Library", "Imported function"]
FIELD_EXENAME = 0
FIELD_LIBNAME = 1
FIELD_IMPORT = 2

def get_pe_imports(arg_fname_list):
    
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
    print("LightW's Malana - \"Get PE Imports\"")
    print()

    parser = argparse.ArgumentParser(description = "List imported symbols of PE files")
    parser.add_argument(
        "filename",
        type = str,
        nargs = '+',
        help = "Name of the file to be analyzed"
    )
    parser.add_argument(
        "-o",
        metavar = "csvoutput",
        type = str,
        required = False,
        help = "Output file where data is written in CSV format"
    )
    args = parser.parse_args()
    fname_set = set(args.filename)
        
    data = get_pe_imports(fname_set)
    if args.o == None:
        print()
        write_console_output(data)
    else:
        write_csv_data(data, pe_imp_fields, args.o)
        print("Imported symbols of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
