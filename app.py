import tkinter as tk
from tkinter import ttk, messagebox
import mysql.connector
import bcrypt

conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Lushane27#01",
    database="music_db"
)
cursor = conn.cursor()

# Function to fetch music recommendations from MySQL database
def get_recommendations():
    # Query to get music recommendations (example query)
    cursor.execute("SELECT title, artist FROM recommendations LIMIT 5")
    recommendations = cursor.fetchall()

    # Format recommendations as HTML
    result = "<ul>"
    for title, artist in recommendations:
        result += f"<li>{title} by {artist}</li>"
        result += "</ul>"
    return result



def sign_up():
    name = name_entry.get()
    email = email_entry.get()
    password = password_entry.get()
    verify_password = verify_password_entry.get()

    if password == verify_password:
        try:
            salt = bcrypt.gensalt()
            hashed_password = bcrypt.hashpw(password.encode(), salt)
            query = "INSERT INTO User (name, email, hashed_password, salt) VALUES (%s, %s, %s, %s)"
            cursor.execute(query, (name, email, hashed_password, salt))
            conn.commit()
            messagebox.showinfo("Success", "User added successfully!")
        except mysql.connector.Error as e:
            messagebox.showerror("Database Error", f"Error adding user: {e}")
    else:
        messagebox.showerror("Passwords do not match. Please try again.")
# Start the application
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("400x300")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    signin_frame = ttk.Frame(root, padding=" 3 3 12 12")
    signin_frame.grid(column=0, row=0, sticky="N, W, E, S")


    signup_frame = ttk.Frame(root, padding=" 3 3 12 12")
    signup_frame.grid(column=0, row=0, sticky="N, W, E, S")

    ttk.Label(signup_frame, text="Name:").grid(column=0, row=0, sticky=tk.W)
    name_entry = ttk.Entry(signup_frame, width=25)
    name_entry.grid(column=1, row=0, sticky="W, E")

    # Email input
    ttk.Label(signup_frame, text="Email:").grid(column=0, row=1, sticky=tk.W)
    email_entry = ttk.Entry(signup_frame, width=25)
    email_entry.grid(column=1, row=1, sticky="W, E")

    # Password input
    ttk.Label(signup_frame, text="Password:").grid(column=0, row=2, sticky="W")
    password_entry = ttk.Entry(signup_frame, width=25, show="*")
    password_entry.grid(column=1, row=2, sticky="W, E")

    ttk.Label(signup_frame, text="Verify Password:").grid(column=0, row=3, sticky="W")
    verify_password_entry = ttk.Entry(signup_frame, width=25, show="*")
    verify_password_entry.grid(column=1, row=3, sticky="W, E")

    # Sign up button
    sign_up_button = ttk.Button(signup_frame, text="Sign up", command=sign_up)
    sign_up_button.grid(column=1, row=4, pady=10, sticky="E")


    root.mainloop()
    cursor.close()
    conn.close()
