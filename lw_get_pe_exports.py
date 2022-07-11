import sys
import pefile
import csv

pe_exp_fields = ["Executable/Library", "Exported symbol"]

def generate_pe_export_list(arg_fname_list):
    list_dict = list()
    pe = 0

    for fname in arg_fname_list:
        try:
            pe = pefile.PE(fname)
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                print("Processing exported symbols: " + fname)
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    list_dict.append({pe_exp_fields[0]: fname, pe_exp_fields[1]: exp.name.decode("utf-8")})
            else:
                print("Have no export section: " + fname)
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return list_dict

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
        
    fname_list = list()
    for i in range(2, argc):
        fname_list.append(sys.argv[i])
        
    with open(sys.argv[1], "w") as outfile:    
        list_dict = generate_pe_export_list(fname_list)
        csvw = csv.DictWriter(outfile, fieldnames = pe_exp_fields)
        csvw.writeheader()
        csvw.writerows(list_dict)
        
        print("Exported symbols of files provided written to " + sys.argv[1])

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
