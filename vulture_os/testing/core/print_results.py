

def print_detailed_results(test_modules):
    """
    Print the detailed results of the tests
    :param test_modules: Dict containing the loaded modules as keys and their test methods as values
    """

    for mod in test_modules:

        if mod.nb_failed:
            print "--------------------------------------------------"
            print " " * (25 - len(str(mod)) / 2) + str(mod)
            print "--------------------------------------------------\n"
            print mod.buffer


def print_summarized_results(test_modules):
    """
    Print a array with the results overview by module
    :param test_modules: Dict containing the loaded modules as keys and their test methods as values
    """

    # Set the minimal length
    length = [
        len('Module'),
        len('Time (seconds)'),
        len('Failed'),
        len('Total'),
    ]

    # Search for the biggest length for each column
    for mod in test_modules:
        length[0] = length[0] if length[0] >= len(str(mod).strip())   else len(str(mod).strip())
        length[1] = length[1] if length[1] >= len(str(mod.time))      else len(str(mod.time))
        length[2] = length[2] if length[2] >= len(str(mod.nb_failed)) else len(str(mod.nb_failed))
        length[3] = length[3] if length[3] >= len(str(mod.nb_test))   else len(str(mod.nb_test))

    # Create the separation line
    sep_line = " *" + ("-" * (reduce(lambda a, b: a + b, length) + 11)) + "*"
    print sep_line

    # Print the title row
    line  = " | Module"         + (" " * (length[0] - 6))
    line += " | Time (seconds)" + (" " * (length[1] - 14))
    line += " | Failed"         + (" " * (length[2] - 6))
    line += " | Total"          + (" " * (length[3] - 5)) + " |"
    print line
    print sep_line

    # Print the overview results for each module
    for mod in test_modules:
        line  = " | " + str(mod).strip()   + (" " * (length[0] - len(str(mod).strip())))
        line += " | " + str(mod.time)      + (" " * (length[1] - len(str(mod.time))))
        line += " | " + str(mod.nb_failed) + (" " * (length[2] - len(str(mod.nb_failed))))
        line += " | " + str(mod.nb_test)   + (" " * (length[3] - len(str(mod.nb_test)))) + " |"
        print line

    print sep_line
