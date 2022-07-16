import malana

print("LightW's Malana - \"VT Scout\"")
print()

(dataset, output) = malana.argparse_build_set(
    arg_description = "Shows last analysis results of given files, searching them by their hashes. Files are NOT submitted to VirusTotal."
)

malana.standalone_function(
    arg_dataset = dataset,
    arg_function = malana.vt_scout,
    arg_fields = malana.analysis_fields,
    arg_output = output
)

print()
print("I'm leaving now, bye bye!")
