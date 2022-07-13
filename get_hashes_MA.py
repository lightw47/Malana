import malana
import argparse

def main():
    print("LightW's Malana - \"Get Hashes\"")
    print()

    parser = argparse.ArgumentParser(description = "List hashes of files")
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
        
    data = malana.get_hashes(fname_set)
    if args.o == None:
        print()
        malana.write_console_output(data)
    else:
        malana.write_csv_data(data, malana.hash_fields, args.o)
        print("Hashes of files provided written to " + args.o)

    print()
    print("I'm leaving now, bye bye!")
    
    
if __name__ == "__main__":
    main()
