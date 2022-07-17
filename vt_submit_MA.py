import malana

print("LightW's Malana - \"VT Submit\"")
print()

(dataset, output) = malana.argparse_build_set(
    arg_description = "Submit files to VirusTotal for scanning."
)

malana.standalone_function(
    arg_dataset = dataset,
    arg_function = malana.vt_submit,
    arg_fields = malana.vt_analysis_fields,
    arg_output = output
)

print()
print("I'm leaving now, bye bye!")
