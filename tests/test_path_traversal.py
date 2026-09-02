from scanner.rules.path_traversal import detect_path_traversal


code = """
filename = input("Enter file name: ")
with open(filename, "r") as file:
    data = file.read()
"""


findings = detect_path_traversal(code)

for finding in findings:
    print(finding)