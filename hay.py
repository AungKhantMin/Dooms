
v=int(input("enter first number"))
g=int(input("enter second number"))

choice=input('what do you want to do?'
             '+ - * /')

if choice=="+":
    a=v+g
    print(a)

elif choice=="-":
    if v>g:
        a=v-g
        print(a)
    else:
        a=g-v
        print(a)

elif choice=="*":
    a=v*g
    print(a)

else:
    a=v/g
    print(a)




