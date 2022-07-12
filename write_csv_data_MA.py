def write_csv_data(arg_dataset, arg_fields, arg_filename):
    with open(arg_filename, "w") as csv_file:
        
        # write fields header
        for i in range(0, len(arg_fields)):
            csv_file.write("\"" + arg_fields[i] + "\"")
            if i != len(arg_fields) - 1:
                csv_file.write(",")

        csv_file.write("\n")

        #write data
        for entry in arg_dataset:

            for i in range(0, len(entry)):
                if entry[arg_fields[i]] != None:
                    csv_file.write("\"" + entry[arg_fields[i]] + "\"")
                if i != len(entry) - 1:
                    csv_file.write(",")

            csv_file.write("\n")