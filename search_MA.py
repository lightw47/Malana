def search(arg_dataset, arg_criteria, arg_key):
    result = set()

    for entry in arg_dataset:

        match = True

        for c in arg_criteria:
            
            if entry[c] != arg_criteria[c]:
                match = False
                break

        if match:
            result.add(entry[arg_key])

    return result
    