from write_console_output_MA import write_console_output
from write_csv_data_MA import write_csv_data
import argparse
import pefile

pe_exp_fields = ["filename", "export"]

def get_pe_exports(arg_fname_list):
    
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
                            "filename": fname,
                            "export": exp.name.decode("utf-8")
                        })

                    else:
                        data.append({
                            "filename": fname,
                            "export": str(exp.ordinal)
                        })
            
            else:
                print("Have no export section: " + fname)
        
        except pefile.PEFormatError:
            print("Is not a PE file: " + fname)
        
        except FileNotFoundError:
            print("File not found: " + fname)
            
    return data

def main():
    print("LightW's Malana - \"Get PE Exports\"")
    print()

    parser = argparse.ArgumentParser(description = "List exported symbols of PE files")
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

    data = get_pe_exports(fname_set)
    if args.o == None:
        print()
        write_console_output(data)
    else:
        write_csv_data(data, pe_exp_fields, args.o)
        print("Exported symbols of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
