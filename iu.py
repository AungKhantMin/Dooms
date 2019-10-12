from sys import argv

filename = argv

print("we are going to erase %r"% filename)
print("if you dont want that, hit CRTL-C")
print("if u do want that, hit RETURN")

input('w')
print ("Opening the file...")
target = open(filename, 'w')
print ("Truncating the file.")
target.trancuate()
print ("Now I'm going to ask you for three lines.")
line1 = input("line 1: ")
line2 = input("line 2: ")
line3 = input("line 3: ")
print ("I'm going to write these to the file.")
target.write(line1)
target.write("\n")

target.write(line2)
target.write("\n")
target.write(line3)
target.write("\n")
print ("And finally, we close it.")
target.close()