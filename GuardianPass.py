import re
import random
import string
import hashlib
import tkinter as tk
from tkinter import messagebox
from datetime import datetime, timedelta

# Keep track of previous hashed passwords and their creation dates
previous_passwords = []

# Initialize failed login attempts counter
failed_login_attempts = 0

# Dark theme color scheme
BACKGROUND_COLOR = "#03001C"
TEXT_COLOR = "#B6EADA"
BUTTON_COLOR = "#5B8FB9"

def apply_dark_theme(widget):
    widget.config(bg=BACKGROUND_COLOR, fg=TEXT_COLOR)

def calculate_password_strength(password):
    length_score = min(2, len(password) // 4)
    uppercase_score = 1 if re.search(r'[A-Z]', password) else 0
    lowercase_score = 1 if re.search(r'[a-z]', password) else 0
    digit_score = 1 if re.search(r'\d', password) else 0
    special_score = 1 if re.search(r'[!@#$%^&*(),.?":{}|<>]', password) else 0

    score = length_score + uppercase_score + lowercase_score + digit_score + special_score
    return score

def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def hash_password(password):
    salt = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    hashed_password = hashlib.sha256((password + salt).encode()).hexdigest()
    return hashed_password, salt

def simulate_password_cracking(password):
    cracked_password = None
    for _ in range(10000):
        candidate_password = generate_random_password(len(password))
        if hash_password(candidate_password)[0] == password:
            cracked_password = candidate_password
            break
    return cracked_password

def check_password():
    password = password_entry.get()

    # Check password against previous passwords
    if password in [hashed for hashed, _, _ in previous_passwords]:
        result_label.config(text="Password is a previous password. Choose a new one.", fg="red")
        return

    strength = calculate_password_strength(password)

    if strength <= 2:
        result_label.config(text="Password is Weak. Consider improving it.", fg="red")
    elif strength <= 4:
        result_label.config(text="Password is Moderate. You can make it stronger.", fg="orange")
    else:
        result_label.config(text="Password is Strong. Good job!", fg="green")

def generate_password():
    generated_password = generate_random_password()
    password_entry.delete(0, tk.END)
    password_entry.insert(0, generated_password)
    check_password()

def hash_and_store_password():
    password = password_entry.get()

    # Hash the password and add it to previous_passwords with creation date
    hashed_password, salt = hash_password(password)
    previous_passwords.append((hashed_password, salt, datetime.now()))
    
    messagebox.showinfo("Password Hashed", f"Hashed Password: {hashed_password}\nSalt: {salt}")

def simulate_cracking():
    password = password_entry.get()
    cracked_password = simulate_password_cracking(hash_password(password)[0])
    if cracked_password:
        messagebox.showinfo("Password Cracked", f"The password was cracked: {cracked_password}")
    else:
        messagebox.showinfo("Password Not Cracked", "The password was not cracked.")

def check_expiry():
    password_expiry_days = 90  # Set the password expiry period in days
    
    if not previous_passwords:
        result_label.config(text="No previous passwords found.", fg="red")
        return
    
    latest_hashed_password, _, creation_date = previous_passwords[-1]
    expiry_date = creation_date + timedelta(days=password_expiry_days)
    current_date = datetime.now()
    
    if current_date > expiry_date:
        result_label.config(text="Password has expired. Please update it.", fg="red")
    else:
        result_label.config(text=f"Password is valid until {expiry_date.strftime('%Y-%m-%d')}.", fg="green")

def toggle_password_visibility():
    current_state = password_entry.cget("show")
    password_entry.config(show="" if current_state == "*" else "*")

def login():
    global failed_login_attempts
    password = password_entry.get()
    
    # Simulate a simple lockout mechanism after 3 failed attempts
    if failed_login_attempts >= 3:
        result_label.config(text="Too many failed login attempts. Please wait.", fg="red")
        return
    
    # Check password against previous passwords
    if hash_password(password)[0] in [hashed for hashed, _, _ in previous_passwords]:
        result_label.config(text="Login successful!", fg="green")
        failed_login_attempts = 0
    else:
        result_label.config(text="Login failed. Please try again.", fg="red")
        failed_login_attempts += 1

def show_password_history():
    history_window = tk.Toplevel(root)
    history_window.title("Password History")
    history_window.config(bg=BACKGROUND_COLOR)

    history_label = tk.Label(history_window, text="Password History", font=("Helvetica", 16, "bold"), fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
    history_label.pack(pady=10)

    if not previous_passwords:
        no_history_label = tk.Label(history_window, text="No password history available.", fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
        no_history_label.pack(pady=10)
    else:
        for idx, (_, _, creation_date) in enumerate(previous_passwords):
            history_text = f"Password {idx + 1}: Created on {creation_date.strftime('%Y-%m-%d %H:%M:%S')}"
            history_entry = tk.Label(history_window, text=history_text, fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
            history_entry.pack(pady=5)

def change_password():
    old_password = old_password_entry.get()
    new_password = new_password_entry.get()

    # Check if the old password matches any of the previous hashed passwords
    if hash_password(old_password)[0] not in [hashed for hashed, _, _ in previous_passwords]:
        result_label.config(text="Old password does not match. Please try again.", fg="red")
        return

    # Check if the new password is the same as the old password
    if old_password == new_password:
        result_label.config(text="New password must be different from the old password.", fg="red")
        return

    # Hash the new password and add it to previous_passwords with creation date
    hashed_password, salt = hash_password(new_password)
    previous_passwords.append((hashed_password, salt, datetime.now()))
    result_label.config(text="Password changed successfully!", fg="green")

def password_strength_meter():
    password = password_entry.get()
    strength = calculate_password_strength(password)

    strength_meter_label.config(text=f"Password Strength: {strength}/5", fg=get_strength_color(strength))

def get_strength_color(strength):
    if strength <= 2:
        return "red"
    elif strength <= 4:
        return "orange"
    else:
        return "green"

root = tk.Tk()
root.title("Password Strength Checker")

# Set dark theme for the root window
root.config(bg=BACKGROUND_COLOR)

password_label = tk.Label(root, text="Enter a password:", fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
password_label.pack(pady=10)

password_entry = tk.Entry(root, show="*")
password_entry.pack(pady=5)

show_password_button = tk.Button(root, text="Show Password", command=toggle_password_visibility, bg=BUTTON_COLOR, fg=TEXT_COLOR)
show_password_button.pack(pady=5)

login_button = tk.Button(root, text="Login", command=login, bg=BUTTON_COLOR, fg=TEXT_COLOR)
login_button.pack(pady=5)

check_button = tk.Button(root, text="Check Password Strength", command=check_password, bg=BUTTON_COLOR, fg=TEXT_COLOR)
check_button.pack(pady=5)

generate_button = tk.Button(root, text="Generate Random Password", command=generate_password, bg=BUTTON_COLOR, fg=TEXT_COLOR)
generate_button.pack(pady=5)

hash_button = tk.Button(root, text="Hash Password and Store", command=hash_and_store_password, bg=BUTTON_COLOR, fg=TEXT_COLOR)
hash_button.pack(pady=5)

simulate_cracking_button = tk.Button(root, text="Simulate Password Cracking", command=simulate_cracking, bg=BUTTON_COLOR, fg=TEXT_COLOR)
simulate_cracking_button.pack(pady=5)

expiry_check_button = tk.Button(root, text="Check Password Expiry", command=check_expiry, bg=BUTTON_COLOR, fg=TEXT_COLOR)
expiry_check_button.pack(pady=5)

result_label = tk.Label(root, text="", fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
result_label.pack(pady=10)

show_password_history_button = tk.Button(root, text="Show Password History", command=show_password_history, bg=BUTTON_COLOR, fg=TEXT_COLOR)
show_password_history_button.pack(pady=5)

change_password_label = tk.Label(root, text="Change Password:", font=("Helvetica", 14, "bold"), fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
change_password_label.pack(pady=10)

old_password_label = tk.Label(root, text="Old Password:", fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
old_password_label.pack()

old_password_entry = tk.Entry(root, show="*")
old_password_entry.pack(pady=5)

new_password_label = tk.Label(root, text="New Password:", fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
new_password_label.pack()

new_password_entry = tk.Entry(root, show="*")
new_password_entry.pack(pady=5)

change_password_button = tk.Button(root, text="Change Password", command=change_password, bg=BUTTON_COLOR, fg=TEXT_COLOR)
change_password_button.pack(pady=5)

strength_meter_label = tk.Label(root, text="Password Strength: N/A", fg=TEXT_COLOR, bg=BACKGROUND_COLOR)
strength_meter_label.pack(pady=5)

password_entry.bind("<KeyRelease>", lambda event: password_strength_meter())

root.mainloop()
