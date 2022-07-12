from get_hashes_MA import FIELD_FILENAME
from write_csv_data_MA import write_csv_data
import sys
import pefile

pe_exp_fields = ["Executable/Library", "Exported symbol"]
FIELD_FILENAME = 0
FIELD_EXPORT = 1

def generate_pe_export_list(arg_fname_list):
    
    data = list()
    pe = 0

    for fname in arg_fname_list:
        
        try:
            pe = pefile.PE(fname)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                print("Processing exported symbols: " + fname)
                
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:

                    if exp.name != None:
                        data.append({
                            pe_exp_fields[FIELD_FILENAME]: fname,
                            pe_exp_fields[FIELD_EXPORT]: exp.name.decode("utf-8")
                        })

                    else:
                        data.append({
                            pe_exp_fields[FIELD_FILENAME]: fname,
                            pe_exp_fields[FIELD_EXPORT]: str(exp.ordinal)
                        })
            
            else:
                print("Have no export section: " + fname)
        
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return data

def main():
    print("LightW's \"Get PE Exports\"")
    print()

    argc = len(sys.argv)

    if argc == 1:
        print("Usage:")
        print("lw_get_pe_exports.py <outfile (csv)> <filename> [filename] [filename] ...")
        exit()

    if argc == 2:
        print("Please, provide at least one file")
        exit()
        
    fname_set = set()
    for i in range(2, argc):
        fname_set.add(sys.argv[i])
        
    data = generate_pe_export_list(fname_set)
    write_csv_data(data, pe_exp_fields, sys.argv[1])

    print("Exported symbols of files provided written to " + sys.argv[1])

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
