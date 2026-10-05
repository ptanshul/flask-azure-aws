
#Create a function that checks whether a number is even
def is_even(number):
    if number % 2 == 0:
        return True
    else:
        return False    

if __name__ == "__main__":
    #Test the function with some numbers
    test_numbers = [1, 2, 3, 4, 5, 6]
    for num in test_numbers:
        if is_even(num):
            print(f"{num} is even.")
        else:
            print(f"{num} is odd.")