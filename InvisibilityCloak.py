#!/usr/bin/env python3
"""
SYNOPSIS

	InvisibilityCloak [-h, --help] [--version] [-m, --method] [-d, --directory] [-n, --name] [-i, --ignore] [-o, --output]

DESCRIPTION

	C# Tool Obfuscator - Works with both Visual Studio solutions (.sln) and single project files (.csproj)

SUPPORTED OBFUSCATION METHODS

	base64 - Base64 encode all strings within project and have them decoded at runtime
	rot13 - Rotate each character in string by 13
	reverse - Reverse all strings within project and have them re-reversed at runtime


EXAMPLES

        ==Run InvisibilityCloak with string obfuscation on a solution==

	InvisibilityCloak.py -d C:\\path\\to\\solution -n "TotallyLegitTool" -m base64
	InvisibilityCloak.py -d C:\\path\\to\\solution -n "TotallyLegitTool" -m rot13
	InvisibilityCloak.py -d C:\\path\\to\\solution -n "TotallyLegitTool" -m reverse


        ==Run InvisibilityCloak with string obfuscation on a single project==

	InvisibilityCloak.py -d C:\\path\\to\\project -n "TotallyLegitTool" -m base64
	InvisibilityCloak.py -d C:\\path\\to\\project -n "TotallyLegitTool" -m rot13
	InvisibilityCloak.py -d C:\\path\\to\\project -n "TotallyLegitTool" -m reverse


	==Run InvisibilityCloak without string obfuscation==

	InvisibilityCloak.py -d C:\\path\\to\\project -n "TotallyLegitTool"


	==Run InvisibilityCloak while ignoring specific projects (solution only)==

	InvisibilityCloak.py -d C:\\path\\to\\solution -n "TotallyLegitTool" -i "CommonDependencies"
	InvisibilityCloak.py -d C:\\path\\to\\solution -n "TotallyLegitTool" -m base64 -i "CommonDependencies,AnotherProject"

	Note: When using the -i/--ignore option, InvisibilityCloak will not rename the specified projects or change their GUIDs,
	      but will update any references to other renamed projects within the ignored projects to maintain compatibility.


	==Run InvisibilityCloak and output mapping to CSV file==

	InvisibilityCloak.py -d C:\\path\\to\\project -n "TotallyLegitTool" -o "mapping.csv"
	InvisibilityCloak.py -d C:\\path\\to\\project -n "TotallyLegitTool" -m base64 -o "mapping.csv"

	Note: The output CSV file will contain a mapping of original project names to their new names, which can be useful
	      for documentation or reference purposes.


	==Use InvisibilityCloak as a library==

	from InvisibilityCloak import apply_cloak

	# Basic usage with a solution
	apply_cloak(directory="C:\\path\\to\\solution", name="TotallyLegitTool")

	# Basic usage with a single project
	apply_cloak(directory="C:\\path\\to\\project", name="TotallyLegitTool")

	# With obfuscation method
	apply_cloak(directory="C:\\path\\to\\project", name="TotallyLegitTool", obf_method="base64")

	# With all options (solution only)
	apply_cloak(
	    directory="C:\\path\\to\\solution",
	    name="TotallyLegitTool",
	    obf_method="base64",
	    ignore_list=["CommonDependencies", "AnotherProject"],
	    output_file="mapping.csv"
	)


BEHAVIOR NOTES

	This version of InvisibilityCloak can work with both Visual Studio solutions (.sln) and single project files (.csproj).
	When working with a solution file, it will rename projects and .csproj files but preserve the original folder structure.
	When working with a single project file, it will rename just that project and its associated files.
	Projects will be renamed with new GUIDs, but all files will remain in their original folders.
	This can be useful when you want to obfuscate a project while maintaining its folder organization.


AUTHOR

	Brett Hawkins (@h4wkst3r)
    @Aconite33

LICENSE

	Apache 2.0 License
	http://www.apache.org/licenses/LICENSE-2.0

VERSION

	0.6

"""
from sys import exit
from uuid import uuid4
from codecs import encode
from shutil import copyfile
from base64 import b64encode
from re import sub, escape, findall, search
from traceback import format_exc as print_traceback
from optparse import OptionParser, TitledHelpFormatter
from os import walk, remove, rename, getcwd, chdir, mkdir, path
import random
import string
import os
import re

# Global dictionary to store original to new name mappings
original_project_names = {}


def generate_random_name() -> str:
    """
    Generate a random 8-character uppercase name
    :return: 8-character random uppercase string
    """
    return ''.join(random.choice(string.ascii_uppercase) for _ in range(8))


def extract_project_info_from_sln(slnFile: str) -> list:
    """
    Extract project information from solution file
    :param slnFile: Path to solution file
    :return: List of dictionaries with project information
    """
    projects = []

    with open(slnFile, 'r', encoding='utf-8', errors='replace') as file:
        sln_content = file.read()

    # Extract project lines using regex pattern - this handles GUIDs with
    # curly braces
    project_pattern = r'Project\("\{([^}]+)\}"\)\s+=\s+"([^"]+)",\s+"([^"]+)",\s+"\{([^}]+)\}"'
    project_matches = findall(project_pattern, sln_content)

    for project_type_guid, name, path_relative, project_guid in project_matches:
        # Replace Windows backslashes with forward slashes first to handle
        # mixed path separators
        if '\\' in path_relative:
            path_relative = path_relative.replace('\\', '/')

        # Then normalize the path for the current OS
        path_relative = os.path.normpath(path_relative)

        # Get folder name from normalized path
        folder_name = os.path.dirname(path_relative)
        if folder_name == "":
            folder_name = name

        # Check if it's a C# project (.csproj)
        if path_relative.endswith(".csproj"):
            projects.append({
                'name': name,
                'path': path_relative,
                # Include curly braces in the GUID
                'guid': "{" + project_guid + "}",
                'folder': folder_name,
                'is_csproj': True
            })
        else:
            projects.append({
                'name': name,
                'path': path_relative,
                # Include curly braces in the GUID
                'guid': "{" + project_guid + "}",
                'folder': folder_name,
                'is_csproj': False
            })

    return projects


def normalize_path_for_os(file_path: str) -> str:
    """
    Helper function to normalize a path for the current OS
    :param file_path: Path to normalize
    :return: Normalized path
    """
    # First replace any Windows backslashes with forward slashes
    if '\\' in file_path:
        file_path = file_path.replace('\\', '/')

    # Then normalize the path for the current OS
    return os.path.normpath(file_path)


def rename_project_files(
        projects: list,
        project_mapping: dict,
        slnFile: str) -> None:
    """
    Rename the .csproj files to match their new project names
    :param projects: List of projects from extract_project_info_from_sln
    :param project_mapping: Mapping of old to new names/GUIDs
    :param slnFile: Path to solution file
    :return: None
    """
    print("\n[*] INFO: Renaming project files")

    for project in projects:
        if project['is_csproj']:
            mapping = project_mapping.get(project['name'])
            if mapping:
                # Skip ignored projects
                if mapping.get('ignored', False):
                    print(
                        f"[*] INFO: Skipping file rename for ignored project: {project['name']}")
                    continue

                # Get the old and new file paths
                old_project_path = os.path.join(
                    os.path.dirname(slnFile), project['path'])
                old_project_path = normalize_path_for_os(old_project_path)

                if os.path.exists(old_project_path):
                    # Get the new project file name
                    old_file_name = os.path.basename(old_project_path)
                    new_file_name = mapping['new_name'] + ".csproj"
                    new_project_path = os.path.join(
                        os.path.dirname(old_project_path), new_file_name)
                    new_project_path = normalize_path_for_os(new_project_path)

                    try:
                        print(
                            f"[*] INFO: Renaming project file {old_project_path} to {new_project_path}")
                        rename(old_project_path, new_project_path)
                    except Exception as e:
                        print(
                            f"[!] WARNING: Could not rename project file {old_project_path}: {str(e)}")
                else:
                    print(
                        f"[!] WARNING: Project file not found for renaming: {old_project_path}")
                    # Try an alternative approach with raw path for debugging
                    raw_project_path = os.path.join(os.path.dirname(
                        slnFile), project['path'].replace('\\', '/'))
                    if os.path.exists(raw_project_path):
                        # Get the new project file name
                        old_file_name = os.path.basename(raw_project_path)
                        new_file_name = mapping['new_name'] + ".csproj"
                        new_project_path = os.path.join(
                            os.path.dirname(raw_project_path), new_file_name)
                        new_project_path = normalize_path_for_os(
                            new_project_path)

                        try:
                            print(
                                f"[*] INFO: Renaming project file {raw_project_path} to {new_project_path}")
                            rename(raw_project_path, new_project_path)
                        except Exception as e:
                            print(
                                f"[!] WARNING: Could not rename project file {raw_project_path}: {str(e)}")
            else:
                print(
                    f"[!] WARNING: No mapping found for project: {project['name']}")


def rename_project_folders(theDirectory: str, project_mapping: dict) -> None:
    """
    Rename project folders based on mapping
    :param theDirectory: Base directory
    :param project_mapping: Mapping of old to new names
    :return: None
    """
    print("\n[*] INFO: Skipping project folder renaming as requested")
    # Folder renaming has been disabled
    return


def reverseString(s: str) -> str:
    """
    method to reverse a given string
    :param s: string to reversse
    :return: string reversed
    """
    new_str = ""
    for i in s:
        new_str = i + new_str
    return new_str


def isLineMethodSignature(theLine: str) -> int:
    """
    method to determine if line is part of a method signature (can't have dynamic strings in method singature)
    :param theLine:
    :return: 0 if not and 1 if the string contains the method signature
    """
    if ("public" in theLine or "private" in theLine) and "string" in theLine and "=" in theLine and "(" in theLine and ")" in theLine:
        return 1
    else:
        return 0


def canProceedWithObfuscation(theLine: str, theItem: str) -> int:
    """
    method to determine if ok to proceed with string obfuscation
    :param theLine: line of file
    :param theItem: strings of line with old tool name occurrence replaced
    :return: zero if can't obfuscate and 1 if ok
    """
    # only obfuscate string if greater than 2 chars
    if len(theItem) <= 2:
        return 0
    # don't obfuscate string if using string interpolation
    elif ("{" in theItem or "}" in theItem and "$" in theLine) or ("String.Format(" in theLine or "string.Format(" in theLine):
        return 0
    # can't obfuscate case statements as they need to be static values
    elif theLine.strip().startswith("case") == 1:
        return 0
    # can't obfuscate const vars
    elif "const string " in theLine or "const static string" in theLine:
        return 0
    # can't obfuscate strings being compared with "is" as they must be static
    elif ("if(" in theLine or "if (" in theLine) and " is \"" in theLine:
        return 0
    # can't obfuscate strings in method signatures
    elif isLineMethodSignature(theLine) == 1:
        return 0
    # obfuscating strings in regexes has been problematic
    elif "new Regex" in theLine or "Regex" in theLine:
        return 0
    # obfuscating unicode strings has been problematic
    elif "Encoding.Unicode.GetString" in theLine or "Encoding.Unicode.GetBytes" in theLine:
        return 0
    # obfuscating occurrence of this has been problematic
    elif "Encoding.ASCII.GetBytes" in theLine:
        return 0
    # can't obfuscate override strings
    elif "public override string" in theLine or "private override string" in theLine:
        return 0
    # don't obfuscate string that starts with or ends with '
    elif theItem.startswith("'") == 1 or theItem.endswith("'") == 1:
        return 0
    # random edge case issue with ""' in line
    elif "\"\"\'" in theLine:
        return 0
    # random edge case issue
    elif "+ @\"" in theLine or "+@\"" in theLine:
        return 0
    # random edge case issue (""" in the line)
    elif "\"\"\"" in theLine:
        return 0
    # random edge case issue ("" in the line)
    elif "\"\"" in theLine:
        return 0
    # random edge case issue (" => " in the line in switch statement)
    elif "\" => \"" in theLine or "\"=>\"" in theLine:
        return 0
    # random edge case issue (" at start of line and ending in "])). this
    # indicates a command line switch that needs to be static
    elif theLine.strip().startswith("\"") == 1 and theLine.strip().endswith("\")]"):
        return 0
    # otherwise, it is ok to proceed with string obfuscation
    else:
        return 1


def stringObfuscate(
        theFile: str,
        project_mapping: dict,
        theObfMethod: str) -> None:
    """
    method to obfuscate strings based on method entered by user
    :param theFile: filepath to obfuscate the strings
    :param project_mapping: mapping of old project names to new names and GUIDs
    :param theObfMethod: obfuscation method
    :return: None
    """
    # Find the project this file belongs to
    file_project_name = None
    for old_name, mapping in project_mapping.items():
        if old_name in theFile:
            file_project_name = old_name
            break

    # Skip if this file belongs to an ignored project
    if file_project_name and project_mapping.get(
        file_project_name,
        {}).get(
        'ignored',
            False):
        print(
            f"[*] INFO: Skipping string obfuscation for file in ignored project: {theFile}")
        return

    if theObfMethod == "base64":
        print(
            f"[*] INFO: Performing base64 obfuscation on strings in {theFile}")

    if theObfMethod == "rot13":
        print(
            f"[*] INFO: Performing rot13 obfuscation on strings in {theFile}")

    if theObfMethod == "reverse":
        print(
            f"[*] INFO: Performing reverse obfuscation on strings in {theFile}")

    # make copy of source file that modifications will be written to
    copyfile(theFile, f"{theFile}_copy")
    try:
        with open(theFile, 'r', encoding='utf-8', errors='replace') as fIn:
            theLines = fIn.readlines()
    except UnicodeDecodeError:
        # If UTF-8 fails, try with Latin-1 which should never fail
        with open(theFile, 'r', encoding='latin-1') as fIn:
            theLines = fIn.readlines()

    fInCopy = open(f"{theFile}_copy", "w", encoding='utf-8')

    index = -1
    # get all lines in the source code file

    # manipulate first line of the source code file as appropriate
    if theLines[0].startswith("#define") == 1:
        theLines[0] = theLines[0].replace(
            "using System.Text;",
            "").replace(
            "using System.Linq;",
            "").replace(
            "using System;",
            "")
        theLines[0] += "\r\nusing System.Text;\r\nusing System.Linq;\r\nusing System;\r\n"

    elif theLines[0].startswith("#define") == 0:
        theLines[0] = theLines[0].replace(
            "using System.Text;",
            "").replace(
            "using System.Linq;",
            "").replace(
            "using System;",
            "")
        theLines[
            0] = f"//start\r\nusing System.Text;\r\nusing System.Linq;\r\nusing System;\r\n{theLines[0]}"

    # Extract the base filename without path or extension
    file_basename = os.path.basename(theFile)
    if file_basename.endswith('.cs'):
        file_basename = file_basename[:-3]  # Remove .cs extension

    # iterate through all of the lines in the source code file
    for line in theLines:
        index += 1
        stringsInLine, substringCount, strippedLine = "", 0, ""

        if line.strip().startswith("[") == 0:
            strippedLine = line

            if index >= 2:
                if theLines[index -
                            2].strip().startswith("[") == 0 and theLines[index -
                                                                         3].strip().startswith("[") == 0:
                    substringCount = strippedLine.count("\\" + "\"")
            else:
                substringCount = strippedLine.count("\\" + "\"")

            # if the line has an embedded string (\"something\"), handle it
            if substringCount >= 2 and "@" not in strippedLine and "\"" + "\\\\" + "\"" not in strippedLine and "public override string" not in strippedLine and "\\\\" + \
                    "\"\"" not in strippedLine and "String.Format(" not in strippedLine and "string.Format(" not in strippedLine:
                strippedLine = strippedLine.replace(
                    "\\" + "\"", "++====THISGETSREPLACED====++")

            # find all strings in the line and add to an array
            stringsInLine = findall(r'"([^"]*)"', strippedLine)

        # if there are strings in the line, then replace them appropriately
        if len(stringsInLine) > 0:
            # replace occurrences of any project names with their new names
            for old_name, mapping in project_mapping.items():
                strippedLine = strippedLine.replace(
                    old_name, mapping['new_name'])

            for theItem in stringsInLine:
                # determine whether can proceed with string obfuscation
                if canProceedWithObfuscation(line, theItem):
                    theString = theItem

                    # if string obfuscation method is base64
                    if theObfMethod == "base64":
                        base64EncodedString = b64encode(
                            theString.encode("utf-8"))
                        theBase64String = str(base64EncodedString)
                        theBase64String = theBase64String.replace(
                            "b'", "").replace("'", "")

                        # if the line has escaped strings (e.g., \r, \t, etc.)
                        if "\\r" in strippedLine or "\\n" in strippedLine or "\\t" in strippedLine or "\"" in strippedLine or "\'" in strippedLine:
                            if "++====THISGETSREPLACED====++" in strippedLine:
                                strippedLine = strippedLine.replace(
                                    "++====THISGETSREPLACED====++", "\\" + "\"")  # remove placeholder strings
                                strippedLine = strippedLine.replace(
                                    "\"" +
                                    theString +
                                    "\"",
                                    "Encoding.UTF8.GetString(Convert.FromBase64String(@" +
                                    "\"" +
                                    theBase64String +
                                    "\"" +
                                    "))")
                            else:
                                strippedLine = strippedLine.replace(
                                    "\"" +
                                    theString +
                                    "\"",
                                    "Encoding.UTF8.GetString(Convert.FromBase64String(" +
                                    "\"" +
                                    theBase64String +
                                    "\"" +
                                    "))")

                            strippedLine = strippedLine.replace(
                                "@Encoding.UTF8.GetString(Convert.FromBase64String",
                                "Encoding.UTF8.GetString(Convert.FromBase64String")
                            strippedLine = strippedLine.replace(
                                "$Encoding.UTF8.GetString(Convert.FromBase64String",
                                "Encoding.UTF8.GetString(Convert.FromBase64String")

                        # if the line does not have escaped strings
                        else:
                            strippedLine = strippedLine.replace(
                                "++====THISGETSREPLACED====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "\"" +
                                theString +
                                "\"",
                                "Encoding.UTF8.GetString(Convert.FromBase64String(@" +
                                "\"" +
                                theBase64String +
                                "\"" +
                                "))")
                            strippedLine = strippedLine.replace(
                                "@Encoding.UTF8.GetString(Convert.FromBase64String",
                                "Encoding.UTF8.GetString(Convert.FromBase64String")
                            strippedLine = strippedLine.replace(
                                "$Encoding.UTF8.GetString(Convert.FromBase64String",
                                "Encoding.UTF8.GetString(Convert.FromBase64String")

                    # if string obfuscation method is rot13
                    if theObfMethod == "rot13":
                        rot13String = encode(theString, "rot_13")

                        # if the line has escaped strings
                        if "\\r" in strippedLine or "\\n" in strippedLine or "\\t" in strippedLine or "\"" in strippedLine or "\'" in strippedLine:
                            if "++====THISGETSREPLACED====++" in strippedLine and "\"" not in strippedLine and "\'" not in strippedLine:
                                strippedLine = strippedLine.replace(
                                    "\"" +
                                    theString +
                                    "\"",
                                    "new string(@" +
                                    "\"" +
                                    rot13String +
                                    "\"" +
                                    ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())")
                            else:
                                strippedLine = strippedLine.replace(
                                    "\"" +
                                    theString +
                                    "\"",
                                    "new string(" +
                                    "\"" +
                                    rot13String +
                                    "\"" +
                                    ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())")

                            strippedLine = strippedLine.replace(
                                "\\e",
                                "\\\\e").replace(
                                "\\g",
                                "\\\\g").replace(
                                "\\\\\\e",
                                "\\\\e").replace(
                                "\\\\\\g",
                                "\\\\g")
                            strippedLine = strippedLine.replace(
                                "++====THISGETSREPLACED====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "++====GUVFTRGFERCYNPRQ====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "@new string(", "new string(@").replace("$new string(", "new string(")

                        # if the line does not have escaped strings
                        else:
                            strippedLine = strippedLine.replace(
                                "\"" +
                                theString +
                                "\"",
                                "new string(@" +
                                "\"" +
                                rot13String +
                                "\"" +
                                ".Select(xAZ => (xAZ >= 'a' && xAZ <= 'z') ? (char)((xAZ - 'a' + 13) % 26 + 'a') : ((xAZ >= 'A' && xAZ <= 'Z') ? (char)((xAZ - 'A' + 13) % 26 + 'A') : xAZ)).ToArray())")
                            strippedLine = strippedLine.replace(
                                "++====THISGETSREPLACED====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "++====GUVFTRGFERCYNPRQ====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "@new string(", "new string(@").replace("$new string(", "new string(")

                    # if string obfuscation method is reverse
                    if theObfMethod == "reverse":
                        reversedString = reverseString(theString)

                        # if the line has escaped strings (e.g., \r, \t, etc.)
                        if "\\r" in strippedLine or "\\n" in strippedLine or "\\t" in strippedLine or "\"" in strippedLine or "\'" in strippedLine:
                            if "++====THISGETSREPLACED====++" in strippedLine:
                                strippedLine = strippedLine.replace(
                                    "\"" +
                                    theString +
                                    "\"",
                                    "new string(@" +
                                    "\"" +
                                    reversedString +
                                    "\"" +
                                    ".ToCharArray().Reverse().ToArray())")
                            else:
                                strippedLine = strippedLine.replace(
                                    "\"" +
                                    theString +
                                    "\"",
                                    "new string(" +
                                    "\"" +
                                    reversedString +
                                    "\"" +
                                    ".ToCharArray().Reverse().ToArray())")

                            strippedLine = strippedLine.replace(
                                "r\\",
                                "r\\\\").replace(
                                "t\\",
                                "t\\\\").replace(
                                "n\\",
                                "n\\\\").replace(
                                "r\\\\\\",
                                "r\\\\").replace(
                                "n\\\\\\",
                                "n\\\\").replace(
                                "t\\\\\\",
                                "t\\\\")
                            strippedLine = strippedLine.replace(
                                "++====DECALPERSTEGSIHT====++", "\"\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "++====THISGETSREPLACED====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "@new string(", "new string(@").replace("$new string(", "new string(")
                            strippedLine = strippedLine.replace(
                                "r\\\\\\",
                                "r\\\\").replace(
                                "n\\\\\\",
                                "n\\\\").replace(
                                "t\\\\\\",
                                "t\\\\")

                        # if the line does not have escaped strings
                        else:
                            strippedLine = strippedLine.replace(
                                "\"" +
                                theString +
                                "\"",
                                "new string(@" +
                                "\"" +
                                reversedString +
                                "\"" +
                                ".ToCharArray().Reverse().ToArray())")
                            strippedLine = strippedLine.replace(
                                "++====DECALPERSTEGSIHT====++", "\"\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "++====THISGETSREPLACED====++", "\\" + "\"")  # remove placeholder strings
                            strippedLine = strippedLine.replace(
                                "@new string(", "new string(@").replace("$new string(", "new string(")

            # remove any placeholder string that wasn't a string candidate
            # originally
            strippedLine = strippedLine.replace(
                "++====THISGETSREPLACED====++", "")
            fInCopy.write(strippedLine)

        # remove duplicate libraries for ones that are included for string
        # deobfuscation
        elif "using System.Linq;" in line and "//start" not in line and "#define" not in line:
            line = line.replace("using System.Linq;", "")

        elif "using System.Text;" in line and "//start" not in line and "#define" not in line:
            line = line.replace("using System.Text;", "")

        elif "using System;" in line and "//start" not in line and "#define" not in line:
            line = line.replace("using System;", "")

        # replace namespace references to any project
        elif "namespace" in line:
            for old_name, mapping in project_mapping.items():
                if old_name in line:
                    line = line.replace(old_name, mapping['new_name'])
            fInCopy.write(line)

        # if class has any project name in it, check if it matches the file
        # name first
        elif "class " in line:
            modified_line = line

            # NEW CODE: Check if the line has a class definition matching the
            # filename
            class_name_match = search(r'class\s+([a-zA-Z0-9_]+)', line)
            if class_name_match:
                class_name = class_name_match.group(1)

                # If class name matches file name, don't rename it
                if class_name == file_basename:
                    print(
                        f"[*] INFO: Preserving class name {class_name} in {theFile} as it matches the file name")
                    fInCopy.write(line)
                    continue

            # Process other project name replacements
            for old_name, mapping in project_mapping.items():
                if old_name in line:
                    modified_line = modified_line.replace(
                        old_name, mapping['new_name'])
            fInCopy.write(modified_line)

        # if line is a standard one-line comment (e.g., // something), delete
        # it
        elif line.strip().startswith("//") and "//start\r\nusing System.Text;\r\nusing System.Linq;\r\n" not in line and "*/" not in line and "/*" not in line:
            fInCopy.write("")

        # if using library in class that has project name in it, replace it
        elif line.strip().startswith("using"):
            for old_name, mapping in project_mapping.items():
                if old_name in line:
                    line = line.replace(old_name, mapping['new_name'])
            fInCopy.write(line)

        # replace constructor name if it has project name in it
        elif line.strip().startswith("public ") or line.strip().startswith("private "):
            # NEW CODE: Check if the line has a constructor or method matching
            # the file name
            constructor_match = search(
                r'(public|private)\s+([a-zA-Z0-9_]+)', line)
            if constructor_match:
                constructor_name = constructor_match.group(2)

                # If constructor/method name matches file name, don't rename it
                if constructor_name == file_basename:
                    print(
                        f"[*] INFO: Preserving constructor/method {constructor_name} in {theFile} as it matches the file name")
                    fInCopy.write(line)
                    continue

            modified_line = line
            for old_name, mapping in project_mapping.items():
                if old_name in line:
                    modified_line = modified_line.replace(
                        old_name, mapping['new_name'])
            fInCopy.write(modified_line)

        # replace any occurrence of project names in source code
        elif any(old_name in line for old_name, _ in project_mapping.items()):
            for old_name, mapping in project_mapping.items():
                line = line.replace(old_name, mapping['new_name'])
            fInCopy.write(line)

        # last catch for any of the placeholder strings that need removed
        elif "++====THISGETSREPLACED====++" in line:
            line = line.replace("++====THISGETSREPLACED====++", "")
            fInCopy.write(line)

        # if no modifications need done to the line
        else:
            fInCopy.write(line)

    # close file streams and replace old source file with new modified one
    fInCopy.close()
    remove(theFile)
    rename(f"{theFile}_copy", theFile)


def rename_project_dll_files(theDirectory: str, project_mapping: dict) -> None:
    """
    Rename physical DLL files in the project directory structure
    :param theDirectory: Base directory
    :param project_mapping: Mapping of old to new names
    :return: None
    """
    print("\n[*] INFO: Searching for and renaming DLL files")

    orig_cwd = getcwd()
    chdir(theDirectory)

    # Walk through all files in the directory looking for .dll files
    for r, d, f in walk('.'):
        for file in f:
            if file.endswith(".dll"):
                # Check if this DLL matches any of our project names
                for old_name, mapping in project_mapping.items():
                    # Skip ignored projects
                    if mapping.get('ignored', False):
                        continue

                    if old_name + ".dll" == file:
                        old_file_path = os.path.join(r, file)
                        new_file_name = mapping['new_name'] + ".dll"
                        new_file_path = os.path.join(r, new_file_name)

                        try:
                            print(
                                f"[*] INFO: Renaming DLL file {old_file_path} to {new_file_path}")
                            rename(old_file_path, new_file_path)
                        except Exception as e:
                            print(
                                f"[!] WARNING: Could not rename DLL file {old_file_path}: {str(e)}")

    chdir(orig_cwd)


def rename_project_supporting_files(
        theDirectory: str,
        project_mapping: dict) -> None:
    """
    Rename project supporting files like .snk signature files
    :param theDirectory: Base directory
    :param project_mapping: Mapping of old to new names
    :return: None
    """
    print("\n[*] INFO: Searching for and renaming project supporting files")

    orig_cwd = getcwd()
    chdir(theDirectory)

    # Walk through all files in the directory looking for .snk files
    for r, d, f in walk('.'):
        for file in f:
            if file.endswith(".snk"):
                # Check if this SNK file matches any of our project names
                for old_name, mapping in project_mapping.items():
                    # Skip ignored projects
                    if mapping.get('ignored', False):
                        continue

                    if old_name + ".snk" == file:
                        old_file_path = os.path.join(r, file)
                        new_file_name = mapping['new_name'] + ".snk"
                        new_file_path = os.path.join(r, new_file_name)

                        try:
                            print(
                                f"[*] INFO: Renaming SNK file {old_file_path} to {new_file_path}")
                            rename(old_file_path, new_file_path)
                        except Exception as e:
                            print(
                                f"[!] WARNING: Could not rename SNK file {old_file_path}: {str(e)}")

    chdir(orig_cwd)


def write_mapping_to_csv(output_file: str, project_mapping: dict) -> None:
    """
    Write project name and GUID mapping to a CSV file
    :param output_file: Path to the output CSV file
    :param project_mapping: Mapping of old to new names/GUIDs
    :return: None
    """
    global original_project_names

    print(f"\n[*] INFO: Writing project mapping to CSV file: {output_file}")

    try:
        # Use standard text mode with explicit newline control
        with open(output_file, 'w', newline='') as f:
            # Write header
            f.write("OriginalName,NewName\n")

            # Write each project mapping from the global dictionary
            for original_name, new_name in original_project_names.items():
                # Clean the names and escape any commas in the data
                orig_name = str(original_name).strip()
                if ',' in orig_name:
                    orig_name = f'"{orig_name}"'

                new_name_clean = str(new_name).strip()
                if ',' in new_name_clean:
                    new_name_clean = f'"{new_name_clean}"'

                # Write the line with a newline
                f.write(f"{orig_name},{new_name_clean}\n")

        print(f"[+] SUCCESS: Project mapping written to {output_file}")
    except Exception as e:
        print(f"[-] ERROR: Failed to write mapping to {output_file}: {str(e)}")


def apply_cloak(
        directory,
        name,
        obf_method=None,
        ignore_list=None,
        output_file=None):
    """
    Apply InvisibilityCloak to a C# project - callable from other Python files

    :param directory: Directory containing the C# project
    :param name: New name for the main tool
    :param obf_method: Obfuscation method ('base64', 'rot13', 'reverse', or None for no obfuscation)
    :param ignore_list: List of project names to ignore
    :param output_file: Path to output CSV file for project mapping
    :return: Dictionary containing the mapping of original project names to new names
    """
    global original_project_names
    original_project_names = {}  # Reset the dictionary

    # Validate input parameters
    if not directory or not path.isdir(directory):
        raise ValueError("Directory does not exist or is not provided")

    if not name:
        raise ValueError("New tool name must be provided")

    if obf_method and obf_method not in ["base64", "rot13", "reverse"]:
        raise ValueError(
            "Unsupported obfuscation method. Use 'base64', 'rot13', 'reverse', or None")

    # Call the main function with the provided parameters
    if obf_method is None:
        obf_method = ""

    main(obf_method, directory, name, ignore_list, output_file)

    # Return the mapping dictionary for reference
    return dict(original_project_names)


def main(
        theObfMethod: str,
        theDirectory: str,
        theName: str,
        ignore_list: list = None,
        output_file: str = None) -> None:
    """
    Manages the main procedures of Invisibility Cloak
    :param theObfMethod: obfuscation method
    :param theDirectory: directory of C# project
    :param theName: name of new tool
    :param ignore_list: list of projects to ignore
    :param output_file: path to output CSV file for project mapping
    :return: None
    """
    print("""
	,                 .     .   .        ,-. .         ,
	|         o     o |   o | o |       /    |         |
	| ;-. . , . ,-. . |-. . | . |-  . . |    | ,-. ,-: | ,
	| | | |/  | `-. | | | | | | |   | | \\    | | | | | |<
	' ' ' '   ' `-' ' `-' ' ' ' `-' `-|  `-' ' `-' `-` ' `
					`-'
	""")

    print("====================================================")
    print(f"[*] INFO: String obfuscation method: {theObfMethod}")
    print(f"[*] INFO: Directory of C# project: {theDirectory}")
    print(f"[*] INFO: New tool name for main project: {theName}")
    if ignore_list and len(ignore_list) > 0:
        print(f"[*] INFO: Ignoring projects: {', '.join(ignore_list)}")
    if output_file:
        print(f"[*] INFO: Writing project mapping to: {output_file}")
    print("====================================================")

    # Normalize the input directory path
    theDirectory = normalize_path_for_os(theDirectory)
    print(f"[*] INFO: Normalized directory path: {theDirectory}")

    # Check if we're dealing with a solution file or a single project
    slnFile = None
    csprojFile = None

    # First look for a solution file
    for r, d, f in walk(theDirectory):
        for file in f:
            if file.endswith(".sln"):
                slnFile = os.path.join(r, file)
                slnFile = normalize_path_for_os(slnFile)
                break
        if slnFile:
            break

    # If no solution file found, look for a .csproj file
    if not slnFile:
        for r, d, f in walk(theDirectory):
            for file in f:
                if file.endswith(".csproj"):
                    csprojFile = os.path.join(r, file)
                    csprojFile = normalize_path_for_os(csprojFile)
                    break
            if csprojFile:
                break

    if not slnFile and not csprojFile:
        error_msg = "No solution file (.sln) or project file (.csproj) found in the directory."
        print(f"\n[-] ERROR: {error_msg}\n")
        if __name__ == '__main__':
            exit(0)
        else:
            raise FileNotFoundError(error_msg)

    # Handle single project file case
    if csprojFile and not slnFile:
        print(f"[*] INFO: Found single project file: {csprojFile}")

        # Create a single project mapping
        project_name = os.path.splitext(os.path.basename(csprojFile))[0]
        project_mapping = {
            project_name: {
                'old_name': project_name,
                'new_name': theName,
                'new_guid': str(uuid4()),
                # We'll extract the real GUID from the project file
                'old_guid': str(uuid4()),
                'old_folder': os.path.dirname(csprojFile),
                'new_folder': os.path.dirname(csprojFile),
                'is_main': True,
                'ignored': False
            }
        }

        # Update the project file
        update_csproj_file(
            csprojFile,
            project_mapping[project_name],
            project_mapping)
        update_assembly_info(csprojFile, project_mapping[project_name])

        # Rename the project file
        rename_project_files([{'name': project_name,
                               'path': csprojFile,
                               'is_csproj': True}],
                             project_mapping,
                             csprojFile)

        # Store the mapping
        global original_project_names
        original_project_names = {project_name: theName}

        # Handle string obfuscation if requested
        if theObfMethod != "":
            print("\n[*] INFO: Performing string obfuscation on C# files")
            for r, d, f in walk(theDirectory):
                for file in f:
                    if file.endswith(".cs") and "AssemblyInfo.cs" not in file and not r.endswith(
                            os.path.join("obj", "Debug")) and not r.endswith(os.path.join("obj", "Release")):
                        stringObfuscate(
                            os.path.join(
                                r,
                                file),
                            project_mapping,
                            theObfMethod)

        # Write mapping to CSV if requested
        if output_file:
            write_mapping_to_csv(output_file, project_mapping)

        print(
            f'\n[+] SUCCESS: Your project now has the invisibility cloak applied.\n')
        return

    # Handle solution file case (existing code)
    print(f"[*] INFO: Found solution file: {slnFile}")

    # generate new GUIDs for C# projects and replace tool names
    replaceGUIDAndToolName(theDirectory, theName, ignore_list)

    # Get updated project mapping after replacement
    projects = extract_project_info_from_sln(slnFile)

    # Create mapping of current project names to their GUIDs
    project_mapping = {}
    for project in projects:
        if project['is_csproj']:
            # Check if this is the main project (first project in the solution)
            is_main = project['name'] == theName

            # Check if this project should be ignored
            is_ignored = False
            if ignore_list and project['name'] in ignore_list:
                is_ignored = True
                print(
                    f"[*] INFO: Maintaining ignored status for project: {project['name']}")

            project_mapping[project['name']] = {
                'old_name': project['name'],
                'new_name': project['name'],
                'new_guid': project['guid'],
                'old_guid': project['guid'],
                'old_folder': project['folder'],
                'new_folder': project['folder'],
                'is_main': is_main,
                'ignored': is_ignored
            }

    # Rename any DLL files that match project names
    rename_project_dll_files(theDirectory, project_mapping)

    # Rename supporting files like .snk signature files
    rename_project_supporting_files(theDirectory, project_mapping)

    # if user wants to obfuscate strings, then proceed
    if theObfMethod != "":
        print("\n[*] INFO: Performing string obfuscation on C# files")
        for r, d, f in walk(theDirectory):
            for file in f:
                if file.endswith(".cs") and "AssemblyInfo.cs" not in file and not r.endswith(
                        os.path.join("obj", "Debug")) and not r.endswith(os.path.join("obj", "Release")):
                    # Skip obfuscation for ignored projects
                    should_skip = False
                    if ignore_list:
                        for ignored_project in ignore_list:
                            if ignored_project in r:
                                print(
                                    f"[*] INFO: Skipping string obfuscation for file in ignored project: {os.path.join(r, file)}")
                                should_skip = True
                                break

                    if not should_skip:
                        stringObfuscate(
                            os.path.join(
                                r,
                                file),
                            project_mapping,
                            theObfMethod)

    # Update references to renamed projects in ignored projects' code files
    if ignore_list and len(ignore_list) > 0:
        print(
            "\n[*] INFO: Updating references to renamed projects in ignored projects' code files")
        for r, d, f in walk(theDirectory):
            is_ignored_project = False
            for ignored_project in ignore_list:
                if ignored_project in r:
                    is_ignored_project = True
                    break

            if is_ignored_project:
                for file in f:
                    if file.endswith(".cs") and "AssemblyInfo.cs" not in file and not r.endswith(
                            os.path.join("obj", "Debug")) and not r.endswith(os.path.join("obj", "Release")):
                        update_code_references(
                            os.path.join(r, file), project_mapping)

    # Write project mapping to CSV file if output file is specified
    if output_file:
        write_mapping_to_csv(output_file, project_mapping)

    print(f'\n[+] SUCCESS: Your projects now have the invisibility cloak applied.\n')


def update_code_references(theFile: str, project_mapping: dict) -> None:
    """
    Update references to renamed projects in code files of ignored projects
    :param theFile: filepath to update references in
    :param project_mapping: mapping of old project names to new names and GUIDs
    :return: None
    """
    print(f"[*] INFO: Updating project references in: {theFile}")

    # Create a copy of the source file
    copyfile(theFile, f"{theFile}_copy")
    try:
        with open(theFile, 'r', encoding='utf-8', errors='replace') as fIn:
            file_content = fIn.read()
    except UnicodeDecodeError:
        # If UTF-8 fails, try with Latin-1 which should never fail
        with open(theFile, 'r', encoding='latin-1') as fIn:
            file_content = fIn.read()

    modified = False

    # Replace references to renamed projects
    for old_name, mapping in project_mapping.items():
        # Skip ignored projects
        if mapping.get('ignored', False):
            continue

        # Replace namespace references
        pattern = r'using\s+' + escape(old_name) + r'(\.[^;]+)?;'
        replacement = f'using {mapping["new_name"]}\\1;'
        new_content = sub(pattern, replacement, file_content)
        if new_content != file_content:
            file_content = new_content
            modified = True
            print(
                f"[*] INFO: Updated namespace references from '{old_name}' to '{mapping['new_name']}' in {theFile}")

        # Replace fully qualified type references
        pattern = r'(\W)' + escape(old_name) + r'\.'
        replacement = f'\\1{mapping["new_name"]}.'
        new_content = sub(pattern, replacement, file_content)
        if new_content != file_content:
            file_content = new_content
            modified = True
            print(
                f"[*] INFO: Updated fully qualified type references from '{old_name}' to '{mapping['new_name']}' in {theFile}")

    # Only write back if changes were made
    if modified:
        with open(f"{theFile}_copy", 'w', encoding='utf-8') as fOut:
            fOut.write(file_content)

        remove(theFile)
        rename(f"{theFile}_copy", theFile)


def replaceGUIDAndToolName(
        theDirectory: str,
        theName: str,
        ignore_list: list = None) -> None:
    """
    Method to generate new project GUIDs and rename projects
    :param theDirectory: directory to find the solution
    :param theName: name of the new main tool (first project)
    :param ignore_list: list of projects to ignore
    :return: None
    """
    global original_project_names  # Use the global dictionary
    original_project_names = {}  # Reset the dictionary

    print("\n[*] INFO: Processing Visual Studio solution or project")

    # Find solution file or project file
    slnFile = None
    csprojFile = None

    # First look for a solution file
    for r, d, f in walk(theDirectory):
        for file in f:
            if file.endswith(".sln"):
                slnFile = os.path.join(r, file)
                slnFile = normalize_path_for_os(slnFile)
                break
        if slnFile:
            break

    # If no solution file found, look for a .csproj file
    if not slnFile:
        for r, d, f in walk(theDirectory):
            for file in f:
                if file.endswith(".csproj"):
                    csprojFile = os.path.join(r, file)
                    csprojFile = normalize_path_for_os(csprojFile)
                    break
            if csprojFile:
                break

    if not slnFile and not csprojFile:
        error_msg = "No solution file (.sln) or project file (.csproj) found in the directory."
        print(f"\n[-] ERROR: {error_msg}\n")
        if __name__ == '__main__':
            exit(0)
        else:
            raise FileNotFoundError(error_msg)

    # Handle single project file case
    if csprojFile and not slnFile:
        print(f"[*] INFO: Found single project file: {csprojFile}")

        # Extract project information from the .csproj file
        project_name = os.path.splitext(os.path.basename(csprojFile))[0]

        # Create a single project mapping
        project_mapping = {
            project_name: {
                'old_name': project_name,
                'new_name': theName,
                'new_guid': str(uuid4()),
                # We'll extract the real GUID from the project file
                'old_guid': str(uuid4()),
                'old_folder': os.path.dirname(csprojFile),
                'new_folder': os.path.dirname(csprojFile),
                'is_main': True,
                'ignored': False
            }
        }

        # Store the original to new name mapping
        original_project_names[project_name] = theName

        # Update the project file
        update_csproj_file(
            csprojFile,
            project_mapping[project_name],
            project_mapping)
        update_assembly_info(csprojFile, project_mapping[project_name])

        # Rename the project file
        rename_project_files([{'name': project_name,
                               'path': csprojFile,
                               'is_csproj': True}],
                             project_mapping,
                             csprojFile)

        return

    # Handle solution file case
    print(f"[*] INFO: Found solution file: {slnFile}")

    # Extract project information from the solution file
    projects = extract_project_info_from_sln(slnFile)

    if not projects:
        error_msg = "No projects found in the solution file."
        print(f"\n[-] ERROR: {error_msg}\n")
        if __name__ == '__main__':
            exit(0)
        else:
            raise ValueError(error_msg)

    print(f"[*] INFO: Found {len(projects)} projects in the solution")

    # Store the original solution filename
    sln_filename = os.path.basename(slnFile)

    # Create mapping of old to new names/GUIDs
    main_project = projects[0]  # First project is the main one
    project_mapping = {}

    # Check if main project is in the ignore list - warn the user
    if ignore_list and main_project['name'] in ignore_list:
        print(
            f"[!] WARNING: Main project '{main_project['name']}' is in the ignore list. This might cause unexpected behavior.")
        print(
            f"[!] WARNING: The main project will still be renamed to '{theName}' as specified.")

    # Map the first project (main) to the user-provided name
    project_mapping[main_project['name']] = {
        'old_name': main_project['name'],
        'new_name': theName,
        'new_guid': main_project['guid'],
        'old_guid': main_project['guid'],
        'old_folder': main_project['folder'],
        # Keep the original folder name for the main project
        'new_folder': main_project['folder'],
        'is_main': True,
        'ignored': False  # Main project is never ignored, even if in ignore list
    }
    # Store the original to new name mapping
    original_project_names[main_project['name']] = theName

    # Map the rest of the projects to random names
    for i in range(1, len(projects)):
        project = projects[i]
        if project['is_csproj']:
            # Check if project should be ignored
            if ignore_list and project['name'] in ignore_list:
                print(f"[*] INFO: Ignoring project: {project['name']}")
                project_mapping[project['name']] = {
                    'old_name': project['name'],
                    'new_name': project['name'],  # Keep the same name
                    'new_guid': project['guid'],  # Keep the same GUID
                    'old_guid': project['guid'],
                    'old_folder': project['folder'],
                    'new_folder': project['folder'],  # Keep the same folder
                    'is_main': False,
                    'ignored': True  # Mark as ignored
                }
                # Store the original to new name mapping (same name for ignored
                # projects)
                original_project_names[project['name']] = project['name']
            else:
                random_name = generate_random_name()
                project_mapping[project['name']] = {
                    'old_name': project['name'],
                    'new_name': random_name,
                    'new_guid': project['guid'],
                    'old_guid': project['guid'],
                    'old_folder': project['folder'],
                    # Keep the original folder name
                    'new_folder': project['folder'],
                    'is_main': False,
                    'ignored': False
                }
                # Store the original to new name mapping
                original_project_names[project['name']] = random_name

    # Log the mapping for reference
    print("\n[*] INFO: Project name and GUID mapping:")
    for old_name, mapping in project_mapping.items():
        if mapping.get('ignored', False):
            print(f"  - '{old_name}' → [IGNORED - No changes]")
        else:
            print(
                f"  - '{old_name}' → '{mapping['new_name']}' (GUID: {mapping['old_guid']} → {mapping['new_guid']})")

    # Update the solution file
    update_solution_file(slnFile, project_mapping)

    # Process each project file
    for project in projects:
        if project['is_csproj']:
            # Print detailed path debugging information
            print(f"[*] DEBUG: Project name: {project['name']}")
            print(f"[*] DEBUG: Project path from solution: {project['path']}")
            print(
                f"[*] DEBUG: Solution file directory: {os.path.dirname(slnFile)}")

            # Use os.path.join for cross-platform path handling
            project_path = os.path.join(
                os.path.dirname(slnFile), project['path'])
            print(f"[*] DEBUG: Combined project path: {project_path}")

            # Ensure the path is normalized for the current OS
            project_path = os.path.normpath(project_path)
            print(f"[*] DEBUG: Normalized project path: {project_path}")

            if os.path.exists(project_path):
                print(f"[+] Project file exists: {project_path}")
                mapping = project_mapping.get(project['name'])
                if mapping:
                    print(f"[*] DEBUG: Project mapping: {mapping}")
                    update_csproj_file(project_path, mapping, project_mapping)
                    update_assembly_info(project_path, mapping)
                else:
                    print(
                        f"[!] WARNING: No mapping found for project: {project['name']}")
            else:
                print(f"[!] WARNING: Project file not found: {project_path}")
                # Try an alternative approach with raw path for debugging
                print(
                    f"[!] DEBUG: Checking raw project path from solution: {project['path']}")
                raw_project_path = os.path.join(os.path.dirname(
                    slnFile), project['path'].replace('\\', '/'))
                if os.path.exists(raw_project_path):
                    print(
                        f"[+] Found project using alternative path: {raw_project_path}")
                    mapping = project_mapping.get(project['name'])
                    if mapping:
                        print(f"[*] DEBUG: Project mapping: {mapping}")
                        update_csproj_file(
                            raw_project_path, mapping, project_mapping)
                        update_assembly_info(raw_project_path, mapping)

    # Rename the .csproj files
    rename_project_files(projects, project_mapping, slnFile)

    # Rename project folders (except for main project)
    rename_project_folders(theDirectory, project_mapping)


def update_solution_file(slnFile: str, project_mapping: dict) -> None:
    """
    Update the solution file with new project names and GUIDs
    :param slnFile: Path to solution file
    :param project_mapping: Mapping of old to new names/GUIDs
    :return: None
    """
    print(f"\n[*] INFO: Updating solution file: {slnFile}")

    # Ensure the solution file path is normalized
    slnFile = normalize_path_for_os(slnFile)

    copyfile(slnFile, f"{slnFile}_copy")
    with open(slnFile, 'r', encoding='utf-8', errors='replace') as file:
        sln_content = file.read()

    # Replace Project declarations
    for old_name, mapping in project_mapping.items():
        # Skip ignored projects
        if mapping.get('ignored', False):
            print(
                f"[*] INFO: Skipping solution project declaration updates for ignored project: {old_name}")
            continue

        # Strip curly braces for pattern matching
        old_guid_no_braces = mapping["old_guid"].replace(
            "{", "").replace("}", "")
        new_guid_no_braces = mapping["new_guid"].replace(
            "{", "").replace("}", "")

        # Find project declarations with this format:
        # Project("{PROJECT_TYPE_GUID}") = "ProjectName",
        # "Path\ProjectName.csproj", "{PROJECT_GUID}"
        pattern = r'Project\("\{([^}]+)\}"\)\s+=\s+"' + escape(old_name) + \
            r'",\s+"([^"]+)",\s+"\{' + escape(old_guid_no_braces) + r'\}"'

        def replacement_func(match):
            project_type_guid = match.group(1)  # The project type GUID
            path = match.group(2)  # The path to the .csproj file

            # Update the path to use the new project name but keep the same
            # folder structure
            if '\\' in path:
                # Windows-style paths in the solution file
                if path.endswith(f"{old_name}.csproj"):
                    # Simple case: just the project name needs to be changed
                    new_path = path.replace(
                        f"{old_name}.csproj", f"{mapping['new_name']}.csproj")
                else:
                    # Path may have folders that match the project name - we
                    # need to be careful
                    path_parts = path.split('\\')

                    # Check if the last part is the .csproj file
                    if path_parts[-1].endswith(".csproj"):
                        path_parts[-1] = f"{mapping['new_name']}.csproj"
                        new_path = '\\'.join(path_parts)
                    else:
                        # Just replace the last occurrence of the project name
                        last_index = path.rindex(old_name)
                        new_path = path[:last_index] + mapping['new_name'] + \
                            path[last_index + len(old_name):]
            else:
                # Unix-style paths in the solution file
                if path.endswith(f"{old_name}.csproj"):
                    # Simple case: just the project name needs to be changed
                    new_path = path.replace(
                        f"{old_name}.csproj", f"{mapping['new_name']}.csproj")
                else:
                    # Path may have folders that match the project name - we
                    # need to be careful
                    path_parts = path.split('/')

                    # Check if the last part is the .csproj file
                    if path_parts[-1].endswith(".csproj"):
                        path_parts[-1] = f"{mapping['new_name']}.csproj"
                        new_path = '/'.join(path_parts)
                    else:
                        # Just replace the last occurrence of the project name
                        last_index = path.rindex(old_name)
                        new_path = path[:last_index] + mapping['new_name'] + \
                            path[last_index + len(old_name):]

            # Format the new project declaration with the updated name, path,
            # and GUID
            return f'Project("{{{project_type_guid}}}") = "{mapping["new_name"]}", "{new_path}", "{{{new_guid_no_braces}}}"'

        # Apply the replacement
        sln_content = sub(pattern, replacement_func, sln_content)

        # Replace GUID references elsewhere in the file (like in
        # ProjectDependencies)
        old_guid_formatted = "{" + old_guid_no_braces + "}"
        new_guid_formatted = "{" + new_guid_no_braces + "}"
        sln_content = sln_content.replace(
            old_guid_formatted, new_guid_formatted)

    # Make sure to update references to non-ignored projects within the
    # GlobalSection sections
    global_sections = findall(
        r'GlobalSection\([^)]+\) = (\w+).*?EndGlobalSection',
        sln_content,
        re.DOTALL)
    for section in global_sections:
        original_section = section

        # For each non-ignored project, update its GUID in the GlobalSection
        for old_name, mapping in project_mapping.items():
            if not mapping.get('ignored', False):
                old_guid_no_braces = mapping["old_guid"].replace(
                    "{", "").replace("}", "")
                new_guid_no_braces = mapping["new_guid"].replace(
                    "{", "").replace("}", "")

                old_guid_formatted = "{" + old_guid_no_braces + "}"
                new_guid_formatted = "{" + new_guid_no_braces + "}"

                # Replace the GUID in this section
                section = section.replace(
                    old_guid_formatted, new_guid_formatted)

        # Update the section in the solution content
        if section != original_section:
            sln_content = sln_content.replace(original_section, section)

    with open(f"{slnFile}_copy", 'w', encoding='utf-8') as file:
        file.write(sln_content)

    remove(slnFile)
    rename(f"{slnFile}_copy", slnFile)


def update_csproj_file(
        csprojFile: str,
        mapping: dict,
        project_mapping: dict) -> None:
    """
    Update a project file with new name and GUID
    :param csprojFile: Path to .csproj file
    :param mapping: Mapping for this specific project
    :param project_mapping: Complete mapping of all projects
    :return: None
    """
    # For ignored projects, handle differently - only update references to
    # other projects
    is_ignored = mapping.get('ignored', False)
    if is_ignored:
        print(
            f"[*] INFO: Processing references in ignored project: {mapping.get('old_name', 'Unknown')}")
    else:
        print(f"[*] INFO: Updating project file: {csprojFile}")

    # Ensure mapping has old_name key (fallback to key in project_mapping)
    if 'old_name' not in mapping:
        for key, map_value in project_mapping.items():
            if map_value.get('new_guid') == mapping.get('new_guid'):
                mapping['old_name'] = key
                print(f"[*] INFO: Found missing old_name '{key}' for project")
                break
        if 'old_name' not in mapping:
            # Still not found, try to extract from file name
            file_name = os.path.basename(csprojFile)
            if file_name.endswith('.csproj'):
                possible_name = file_name[:-7]  # Remove .csproj extension
                mapping['old_name'] = possible_name
                print(
                    f"[*] INFO: Using file name '{possible_name}' as old_name for project")

    copyfile(csprojFile, f"{csprojFile}_copy")
    try:
        with open(csprojFile, 'r', encoding='utf-8', errors='replace') as file:
            csproj_content = file.read()
    except UnicodeDecodeError:
        # If UTF-8 fails, try with Latin-1 which should never fail
        with open(csprojFile, 'r', encoding='latin-1') as file:
            csproj_content = file.read()

    # For non-ignored projects, update their own project info
    if not is_ignored:
        # Replace project GUID
        csproj_content = csproj_content.replace(
            mapping["old_guid"], mapping["new_guid"])

        # Update AssemblyName element to match the new project name
        csproj_content = sub(
            r'<AssemblyName>' +
            escape(
                mapping["old_name"]) +
            r'</AssemblyName>',
            r'<AssemblyName>' +
            mapping["new_name"] +
            r'</AssemblyName>',
            csproj_content)

        # Update RootNamespace element to match the new project name
        csproj_content = sub(
            r'<RootNamespace>' +
            escape(
                mapping["old_name"]) +
            r'</RootNamespace>',
            r'<RootNamespace>' +
            mapping["new_name"] +
            r'</RootNamespace>',
            csproj_content)

        # Update signing key files (.snk)
        csproj_content = sub(
            r'<AssemblyOriginatorKeyFile>' +
            escape(
                mapping["old_name"]) +
            r'\.snk</AssemblyOriginatorKeyFile>',
            r'<AssemblyOriginatorKeyFile>' +
            mapping["new_name"] +
            r'.snk</AssemblyOriginatorKeyFile>',
            csproj_content)

    # Extract and preserve ItemGroup/Compile sections
    compile_items = []
    for match in findall(
        r'<ItemGroup>\s*(?:<Compile[^>]*>\s*)*</ItemGroup>',
            csproj_content):
        if '<Compile ' in match:
            compile_items.append(match)

    # Extract and temporarily remove OutputPath elements to completely protect
    # them from changes
    output_paths = {}

    def replace_output_path(match):
        placeholder = f"OUTPUT_PATH_PLACEHOLDER_{len(output_paths)}"
        output_paths[placeholder] = match.group(0)
        return placeholder

    # Replace all OutputPath elements with unique placeholders
    csproj_content = sub(
        r'<OutputPath>[^<]+</OutputPath>',
        replace_output_path,
        csproj_content)

    # Extract and temporarily remove HintPath elements to protect folder
    # references
    hint_paths = {}

    def replace_hint_path(match):
        placeholder = f"HINT_PATH_PLACEHOLDER_{len(hint_paths)}"
        hint_paths[placeholder] = match.group(0)

        # For DLL names that match a project name, still update those
        hint_path_content = match.group(0)
        dll_name_match = search(
            r'([^\\/<>]+)\.dll</HintPath>',
            hint_path_content)

        if dll_name_match:
            dll_name = dll_name_match.group(1)
            # If this DLL name matches a project name that's being renamed,
            # update just the DLL name
            for old_proj_name, proj_mapping in project_mapping.items():
                if dll_name == old_proj_name and not proj_mapping.get(
                        'ignored', False):
                    # Replace just the DLL name, preserving the path
                    new_hint_path = hint_path_content.replace(
                        f"{dll_name}.dll</HintPath>",
                        f"{proj_mapping['new_name']}.dll</HintPath>"
                    )
                    hint_paths[placeholder] = new_hint_path
                    break

        return placeholder

    # Replace all HintPath elements with unique placeholders
    csproj_content = sub(
        r'<HintPath>[^<]+</HintPath>',
        replace_hint_path,
        csproj_content)

    # Replace references to other renamed projects for ALL projects (including ignored ones)
    # This is the key change - we want to update references even in ignored
    # projects
    for old_name, other_mapping in project_mapping.items():
        # Skip self-references if processing an ignored project
        if is_ignored and old_name == mapping['old_name']:
            continue

        # Skip references to other ignored projects
        if other_mapping.get('ignored', False):
            continue

        # Replace direct GUID references
        csproj_content = csproj_content.replace(
            other_mapping["old_guid"], other_mapping["new_guid"])

        # Handle specific DLL references in Reference Include and EmbeddedResource elements
        # Match References like: <Reference Include="ProjectName"> or
        # <Reference Include="ProjectName.Something">
        csproj_content = sub(
            r'<Reference Include="' + escape(old_name) + r'([^"]*)"',
            r'<Reference Include="' + other_mapping["new_name"] + r'\1"',
            csproj_content
        )

        # Match DLL files in EmbeddedResource like: <EmbeddedResource
        # Include="path\ProjectName.dll" />
        csproj_content = sub(
            r'<EmbeddedResource Include="([^<]*)' +
            escape(old_name) +
            r'\.dll"',
            r'<EmbeddedResource Include="\1' +
            other_mapping["new_name"] +
            r'.dll"',
            csproj_content)

        # Use a targeted approach for project name replacement, excluding Compile Include sections
        # First, split the content into sections around ItemGroup containing
        # Compile elements
        parts = []
        current_pos = 0

        for item in compile_items:
            start_pos = csproj_content.find(item, current_pos)
            if start_pos > current_pos:
                # Process the content before this ItemGroup
                section = csproj_content[current_pos:start_pos]
                section = sub(
                    r'(?i)' + escape(old_name),
                    other_mapping["new_name"],
                    section)
                parts.append(section)

            # Add the ItemGroup with Compile elements unchanged
            parts.append(item)
            current_pos = start_pos + len(item)

        # Add any remaining content after the last ItemGroup
        if current_pos < len(csproj_content):
            section = csproj_content[current_pos:]
            section = sub(
                r'(?i)' + escape(old_name),
                other_mapping["new_name"],
                section)
            parts.append(section)

        # Reconstruct the content
        csproj_content = ''.join(parts)

    # Restore all original OutputPath elements exactly as they were
    for placeholder, original_path in output_paths.items():
        csproj_content = csproj_content.replace(placeholder, original_path)

    # Restore all HintPath elements with appropriate updates
    for placeholder, hint_path in hint_paths.items():
        csproj_content = csproj_content.replace(placeholder, hint_path)

    # Remove PDB debug information (only for non-ignored projects)
    if not is_ignored:
        csproj_content = csproj_content.replace(
            "<DebugType>pdbonly</DebugType>",
            "<DebugType>none</DebugType>")
        csproj_content = csproj_content.replace(
            "<DebugType>full</DebugType>",
            "<DebugType>none</DebugType>")

    with open(f"{csprojFile}_copy", 'w', encoding='utf-8') as file:
        file.write(csproj_content)

    remove(csprojFile)
    rename(f"{csprojFile}_copy", csprojFile)


def update_assembly_info(projectPath: str, mapping: dict) -> None:
    """
    Update AssemblyInfo.cs in the project
    :param projectPath: Path to .csproj file
    :param mapping: Mapping for this specific project
    :return: None
    """
    # Skip if this is an ignored project
    if mapping.get('ignored', False):
        print(
            f"[*] INFO: Skipping assembly info updates for ignored project: {mapping.get('old_name', 'Unknown')}")
        return

    # Ensure mapping has old_name key (fallback to file name)
    if 'old_name' not in mapping:
        file_name = os.path.basename(projectPath)
        if file_name.endswith('.csproj'):
            possible_name = file_name[:-7]  # Remove .csproj extension
            mapping['old_name'] = possible_name
            print(
                f"[*] INFO: Using file name '{possible_name}' as old_name for assembly info")

    # Find the AssemblyInfo.cs file in the project directory
    project_dir = os.path.dirname(projectPath)
    assemblyInfoFile = ""

    for r, d, f in walk(project_dir):
        for file in f:
            if "AssemblyInfo.cs" in file:
                assemblyInfoFile = os.path.join(r, file)
                break
        if assemblyInfoFile:
            break

    if not assemblyInfoFile:
        print(
            f"[!] WARNING: AssemblyInfo.cs not found for project: {projectPath}")
        # Try an alternative approach with normalized paths
        print(
            f"[!] DEBUG: Searching for AssemblyInfo.cs with normalized paths in: {project_dir}")
        project_dir_normalized = os.path.normpath(project_dir)
        for r, d, f in walk(project_dir_normalized):
            for file in f:
                if "AssemblyInfo.cs" in file:
                    assemblyInfoFile = os.path.join(r, file)
                    print(
                        f"[+] Found AssemblyInfo.cs using normalized path: {assemblyInfoFile}")
                    break
            if assemblyInfoFile:
                break

        if not assemblyInfoFile:
            return

    print(f"[*] INFO: Updating assembly info: {assemblyInfoFile}")

    copyfile(assemblyInfoFile, f"{assemblyInfoFile}_copy")
    try:
        with open(assemblyInfoFile, 'r', encoding='utf-8', errors='replace') as file:
            assembly_content = file.read()
    except UnicodeDecodeError:
        # If UTF-8 fails, try with Latin-1 which should never fail
        with open(assemblyInfoFile, 'r', encoding='latin-1') as file:
            assembly_content = file.read()

    # Replace assembly name and GUID
    assembly_content = sub(
        r'(?i)' +
        escape(
            mapping["old_name"]),
        mapping["new_name"],
        assembly_content)

    # Make sure GUID is properly formatted
    old_guid_formatted = mapping["old_guid"].replace(
        "{", "").replace("}", "").lower()
    new_guid_formatted = mapping["new_guid"].replace(
        "{", "").replace("}", "").lower()
    assembly_content = assembly_content.replace(
        old_guid_formatted, new_guid_formatted)

    with open(f"{assemblyInfoFile}_copy", 'w', encoding='utf-8') as file:
        file.write(assembly_content)

    remove(assemblyInfoFile)
    rename(f"{assemblyInfoFile}_copy", assemblyInfoFile)


if __name__ == '__main__':
    try:
        parser = OptionParser(
            formatter=TitledHelpFormatter(),
            usage=globals()['__doc__'],
            version='0.6')
        parser.add_option('-m', '--method', dest='obfMethod',
                          help='string obfuscation method')
        parser.add_option(
            '-d',
            '--directory',
            dest='directory',
            help='directory of C# project')
        parser.add_option('-n', '--name', dest='name', help='new tool name')
        parser.add_option(
            '-i',
            '--ignore',
            dest='ignore',
            help='comma-separated list of projects to ignore (e.g., "CommonDependencies,OtherProject")')
        parser.add_option(
            '-o',
            '--output',
            dest='output',
            help='output CSV file for project mapping (e.g., "mapping.csv")')
        (options, args) = parser.parse_args()

        # if directory or name or not specified, display help and exit
        if options.directory is None or options.name is None:
            print(
                "\n[-] ERROR: You must supply directory of C# project and new name for tool.\n")
            parser.print_help()
            exit(0)

        # if obfuscation method is not supported method, display help and exit
        if options.obfMethod is not None and (
                options.obfMethod != "base64" and options.obfMethod != "rot13" and options.obfMethod != "reverse"):
            print(
                "\n[-] ERROR: You must supply a supported string obfuscation method\n")
            parser.print_help()
            exit(0)

        # if directory provided does not exist, display message and exit
        doesDirExist = os.path.isdir(options.directory)
        if doesDirExist == 0:
            print(
                "\n[-] ERROR: Directory provided does not exist. Please check the path you are providing\n")
            exit(0)

        # initialize variables
        theObfMethod, theDirectory, theName = options.obfMethod, options.directory, options.name
        outputFile = options.output if options.output else None

        # if no obfuscation method supplied
        if theObfMethod is None:
            theObfMethod = ""

        # Parse ignore list if provided
        ignore_list = None
        if options.ignore:
            ignore_list = [proj.strip() for proj in options.ignore.split(',')]
            print(
                f"[*] INFO: The following projects will be ignored: {', '.join(ignore_list)}")

        # Use the new apply_cloak function instead of calling main directly
        apply_cloak(
            directory=theDirectory,
            name=theName,
            obf_method=theObfMethod,
            ignore_list=ignore_list,
            output_file=outputFile
        )

    except KeyboardInterrupt:  # Ctrl-C
        raise
    except SystemExit:  # sys.exit()
        raise
    except FileNotFoundError:
        print("\n[-] ERROR: File not found\n")
        print_traceback()
        exit(1)
    except Exception as e:
        print("\n[-] ERROR: Unexpected exception\n")
        print(f"Exception type: {type(e).__name__}")
        print(f"Exception message: {str(e)}")
        try:
            print_traceback()
        except Exception:
            print("Failed to print detailed traceback. Original error:", str(e))
        exit(1)
