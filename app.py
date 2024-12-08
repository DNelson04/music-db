import datetime
import secrets
import tkinter as tk
from collections import defaultdict
from tkinter import ttk, messagebox
import mysql.connector
import bcrypt
import keyring

conn = mysql.connector.connect(
    host="localhost",
    user="pyapp",
    password="Lushane27#01",
    database="music_db"
)
cursor = conn.cursor()

def create_session(user_id):
    try:
        query = "SELECT user_id FROM UserSessions WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        result = cursor.fetchall()
        if result:
            query = "DELETE FROM UserSessions WHERE user_id = %s"
            cursor.execute(query, (user_id,))
            conn.commit()
        # Generate a unique session ID
        session_id = secrets.token_hex(16)
        keyring.set_password("music_app", "session_id", session_id)

        # Calculate expiration time (e.g., 1 hour from now)
        expiration_time = datetime.datetime.now() + datetime.timedelta(hours=1)

        # Save session in the database
        query = "INSERT INTO UserSessions (session_id, user_id, expires_at) VALUES (%s, %s, %s)"
        cursor.execute(query, (session_id, user_id, expiration_time))
        conn.commit()
        return session_id
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def validate_session(session_id):
    try:
        query = "SELECT user_id, expires_at FROM UserSessions WHERE session_id = %s"
        cursor.execute(query, (session_id,))
        result = cursor.fetchone()

        if result:
            user_id, expires_at = result
            if datetime.datetime.now() < expires_at:
                return user_id  # Session is valid
            else:
                query = "DELETE FROM UserSessions WHERE session_id = %s"
                cursor.execute(query, (session_id,))
                conn.commit()
                keyring.delete_password("music_app", "session_id")
                messagebox.showinfo("Logged out", "Your session has expired. Please sign in again.")
                signin_frame.tkraise()
        else:
            messagebox.showerror("Invalid session", "Invalid session")
        return
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def sign_up(signup_username_entry, signup_email_entry, signup_password_entry, verify_password_entry,):
    username = signup_username_entry.get()
    email = signup_email_entry.get()
    password = signup_password_entry.get()
    verify_password = verify_password_entry.get()

    if not username or not email or not password or not verify_password:
        messagebox.showerror("Error", "All fields are required!")
        return

    if password != verify_password:
        messagebox.showerror("Error", "Passwords do not match!")
        return

    try:
        # Check if user already exists
        query = "SELECT * FROM Users WHERE email = %s OR username = %s"
        cursor.execute(query, (email, username))
        if cursor.fetchone():
            messagebox.showerror("Error", "User already exists with this email or username!")
            return

        # Hash the password and save user
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        query = "INSERT INTO Users (username, email, hashed_password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, hashed_password))
        conn.commit()
        messagebox.showinfo("Success", "User added successfully!")
        signin_frame.tkraise()

    except mysql.connector.Error as e:
        messagebox.showerror("Database Error", f"Error adding user: {e}")

def sign_in(signin_id_entry, signin_password_entry):
    try:
        id = signin_id_entry.get()
        password_attempt = signin_password_entry.get()
        if "@" in id:  # A simple heuristic for emails
            query = "SELECT user_id, hashed_password FROM Users WHERE email = %s"
        else:
            query = "SELECT user_id, hashed_password FROM Users WHERE username = %s"
        cursor.execute(query, (id,))
        result = cursor.fetchone()

        if result is None:
            messagebox.showerror("User Not Found.", f"User Not Found")
            return

        user_id, hashed_pw = result

        if bcrypt.checkpw(password_attempt.encode(), hashed_pw.encode()):
            create_session(user_id)
            home_frame.tkraise()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def search(search_entry):
    """so when i search, i need to look through track, albums and artists, and return a list of all the results, preferrably in popularity order. so, the easiest way ik how to do this would be to
    convert all info to json format and return it as a json object, with structure; response[responseinfo, responseObjects]"""
    search_entry = search_entry.get()
    try:
        # SQL query to search across artists, albums, and tracks
        query = """
            SELECT 
                'artist' AS object_type, 
                a.artist_id AS id, 
                a.name AS title, 
                NULL AS album_id,
                NULL AS album_title,
                NULL AS artist_id,
                NULL AS artist_name,
                a.popularity
            FROM Artists a
            WHERE a.name LIKE CONCAT('%', %s, '%')

            UNION

            SELECT 
                'album' AS object_type, 
                al.album_id AS id, 
                al.title AS title, 
                al.album_id AS album_id,
                al.title AS album_title,
                al.artist_id AS artist_id, 
                a.name AS artist_name, 
                al.popularity
            FROM Albums al
            JOIN Artists a ON al.artist_id = a.artist_id
            WHERE al.title LIKE CONCAT('%', %s, '%')

            UNION

            SELECT 
                'track' AS object_type, 
                t.track_id AS id, 
                t.title AS title, 
                t.album_id AS album_id, 
                al.title AS album_title,
                a.artist_id AS artist_id,
                a.name AS artist_name,
                t.popularity
            FROM Tracks t
            JOIN Albums al ON t.album_id = al.album_id
            JOIN Artists a ON t.artist_id = a.artist_id
            WHERE t.title LIKE CONCAT('%', %s, '%')

            ORDER BY popularity DESC;
        """
        cursor.execute(query, (search_entry, search_entry, search_entry))
        results = cursor.fetchall()
        for item in results:
            print(item)
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def open_playlist(pid):
    try:
        query = """
            SELECT 
                p.name AS playlist_name,
                t.track_id,
                t.title,
                t.album_id,
                t.artist_id,
                t.release_date,
                t.popularity
            FROM 
                playlists p
            JOIN 
                playlistTracks pt ON p.playlist_id = pt.playlist_id
            JOIN 
                tracks t ON pt.track_id = t.track_id
            WHERE 
                p.playlist_id = %s
        """
        cursor.execute(query, (pid,))
        results = cursor.fetchall()
        print(results)

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def go_to_playlists():
    playlists_frame.tkraise()
    update_playlists()

def add_to_playlist(track_id, playlist_id):


def populate_playlist_frame(results):
    for widget in playlists_frame.winfo_children():
        widget.destroy()

        # Add a heading
    ttk.Label(playlists_frame, text="Your Playlists", font=("Arial", 16)).grid(column=0, row=0, pady=10)

    # Dynamically create widgets for each playlist
    for idx, (playlist_id, playlist_name) in enumerate(results, start=1):
        # Display playlist name
        ttk.Label(playlists_frame, text=playlist_name, font=("Arial", 12)).grid(column=0, row=idx, sticky="W", padx=10, pady=5)
        # Add a button for actions (e.g., view or edit)
        ttk.Button(playlists_frame, text="View", command=lambda pid=playlist_id: open_playlist(pid)).grid(column=1, row=idx, padx=10, pady=5)

def update_playlists():
    session_id = keyring.get_password("music_app", "session_id")
    print(session_id)
    try:
        user_id = validate_session(session_id)
        query = "SELECT playlist_id, name FROM Playlists WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        populate_playlist_frame(results)
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return


def create_playlists_frame(panel):
    frame = ttk.Frame(panel, padding = "10 10 10 10")
    frame.grid(column=0, row=0, sticky="N, W, E, S")
    return frame

def create_sign_up_frame(panel):
    frame = ttk.Frame(panel, padding=" 3 3 12 12")
    frame.grid(column=0, row=0, sticky="N, W, E, S")

    ttk.Label(frame, text="Username:").grid(column=0, row=0, sticky="W")
    signup_username_entry = ttk.Entry(frame, width=25)
    signup_username_entry.grid(column=1, row=0, sticky="W, E")

    # Email input
    ttk.Label(frame, text="Email:").grid(column=0, row=1, sticky="W")
    signup_email_entry = ttk.Entry(frame, width=25)
    signup_email_entry.grid(column=1, row=1, sticky="W, E")

    # Password input
    ttk.Label(frame, text="Password:").grid(column=0, row=2, sticky="W")
    signup_password_entry = ttk.Entry(frame, width=25, show="*")
    signup_password_entry.grid(column=1, row=2, sticky="W, E")

    ttk.Label(frame, text="Verify Password:").grid(column=0, row=3, sticky="W")
    verify_password_entry = ttk.Entry(frame, width=25, show="*")
    verify_password_entry.grid(column=1, row=3, sticky="W, E")

    # Sign up button
    sign_up_button = ttk.Button(frame, text="Sign up", command=lambda: sign_up(
            signup_username_entry,
            signup_email_entry,
            signup_password_entry,
            verify_password_entry,
        ))
    sign_up_button.grid(column=1, row=4, pady=5)

    ttk.Button(frame, text="Already have an account? Sign in here", command=lambda: signin_frame.tkraise()).grid(
        column=1, row=5)
    return frame

def create_sign_in_frame(panel):
    frame = ttk.Frame(panel, padding=" 3 3 12 12")
    frame.grid(column=0, row=0, sticky="N, W, E, S")

    ttk.Label(frame, text="Email or Username:").grid(column=0, row=0, sticky="W")
    signin_id_entry = ttk.Entry(frame, width=25)
    signin_id_entry.grid(column=1, row=0, sticky="W, E")

    ttk.Label(frame, text="Password:").grid(column=0, row=1, sticky="W")
    signin_password_entry = ttk.Entry(frame, width=25, show="*")
    signin_password_entry.grid(column=1, row=1, sticky="W, E")

    sign_in_button = ttk.Button(frame, text="Sign in", command=lambda: sign_in(signin_id_entry,signin_password_entry))
    sign_in_button.grid(column=1, row=4, pady=5)
    ttk.Button(frame, text="Dont have an account?", command=lambda: signup_frame.tkraise()).grid(column=1, row=2)

    return frame

def create_home_frame(panel):
    # Main Frame
    frame = ttk.Frame(panel, padding="10 10 10 10")
    frame.grid(column=0, row=0, sticky="N, W, E, S")

    ttk.Label(frame, text="Music App Home", font=("Arial", 20)).grid(column=0, row=0, columnspan=2, pady=10)

    # Buttons for functionalities
    search_entry = ttk.Entry(frame, width=25)
    search_entry.grid(column=0, row=1, sticky="W, E")
    ttk.Button(frame, text="Search App", command= lambda: search(search_entry)).grid(column=1, row=1, padx=10, pady=5)
    ttk.Button(frame, text="Playlists", command=lambda: go_to_playlists()).grid(column=0, row=2, padx=10, pady=5)

    for child in frame.winfo_children():
        child.grid_configure(padx=5, pady=5)

    return frame


# Start the application
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("400x300")
    root.columnconfigure(0, weight=1)
    root.rowconfigure(0, weight=1)

    signin_frame = create_sign_in_frame(root)
    signup_frame = create_sign_up_frame(root)
    home_frame = create_home_frame(root)
    playlists_frame = create_playlists_frame(root)
    signin_frame.tkraise()

    root.mainloop()
    cursor.close()
    conn.close()
