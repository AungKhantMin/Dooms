# Print Test
print("Hello!")

#Variable Test
one = 1
two = 2
three = one + two
print(three)

#List Example
prime_numbers = [2, 3, 5, 7, 11, 13, 17]
print("Primes = ", len(prime_numbers))

for p in prime_numbers:
    print("Primes: ", p)

#Tuple Example
perfect_squares = (1, 4, 9, 16, 25, 36)
print("Squares = ", len(perfect_squares))

for s in perfect_squares:
    print("Squares: ", s)

tuplee = (1, 'aung')
print(tuplee[1])

#String Example
l = [1, "hi", "python", 2]
print(l[3:])
print(l[0:2])
print(l)
print(l+l)
print(l*3)

#Dictionary Example
d = {1: 'Jimmy', 2: 'Alex', 3: 'John', 4: 'Mike'}
print("1st name is "+d[1])
print("2nd name is "+d[4])
print(d)
print(d.keys())
print(d.values())

#Statements Test
num = int(input("Enter number:"))
if num == 0:
    print("Zero")
elif num%2 == 0:
    print("Even")
else:
    print("Odd")

#loop Test
i = 0
n = int(input("Enter number"))
for i in range(1, n+1):
    print(i)
else:print("loop is exhausted")

i = 1
num = int(input("Enter a number"))
for i in range(1, 11):
    print("%d X %d = %d"%(num, i, num*i))

i = 0
for i in range(1, 5):
    print(i)
    break
else:
    print("loop is exhausted")
print("loop is broken")

check = 0
if check == 0:
    pass

str = "hello"
print(type(str))
print(str[2:3])

char = 'a'
print(type(char))

#I am done learning python basic! I just read set dictionary functions and I feel lazy to test them XD