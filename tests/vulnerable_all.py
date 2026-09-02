import os

username = input("Enter username: ")
filename = input("Enter filename: ")
command = input("Enter command: ")

# SQL Injection
query = "SELECT * FROM users WHERE username = '" + username + "'"

# Command Injection
os.system(command)

# Hardcoded Secret
API_KEY = "sk_test_123456789"

# XSS
html = "<h1>" + username + "</h1>"

# Path Traversal
with open(filename, "r") as file:
    data = file.read()

print(query)
print(html)
print(data)