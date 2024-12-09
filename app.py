import datetime
import secrets
import tkinter as tk
from functools import partial
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

class ScrollableFrame(tk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.canvas = tk.Canvas(self)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scrollable_frame = ttk.Frame(self.canvas)

        # Configure the scrollable frame
        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )

        self.canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        # Use grid exclusively
        self.canvas.grid(row=0, column=0, sticky="nsew")
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

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
        else:
            messagebox.showerror("Incorrect Password", "Incorrect password, please try again")
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
        search_results(results)

        for item in results:
            print(item)

        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def search_results(results):
    for widget in search_results_frame.scrollable_frame.winfo_children():
        widget.destroy()

    search_entry = ttk.Entry(search_results_frame.scrollable_frame, width=10)
    search_entry.grid(column=0, row=0, sticky="W")
    ttk.Button(search_results_frame.scrollable_frame, text="Search App", command=lambda: search(search_entry)).grid(column=1, row=0, padx=10, pady=5)
    ttk.Button(search_results_frame.scrollable_frame, text="Back to Home", command=lambda: go_home()).grid(column=2, row=0, padx=10, pady=5, sticky="W")
    ttk.Label(search_results_frame.scrollable_frame, text="Results", font=("Arial", 20)).grid(column=0, row=1, columnspan=2, pady=10, sticky="W")

    for index, (type, id, title, album_id, album_title, artist_id, artist_name, popularity) in enumerate(results, start=2):
        ttk.Label(search_results_frame.scrollable_frame, text=title, font=("Arial", 12)).grid(column=0, row=index * 2, sticky="W")
        ttk.Label(search_results_frame.scrollable_frame, text=artist_name, font=("Arial", 8)).grid(column=0, row=index * 2 + 1, sticky="W")
        ttk.Button(search_results_frame.scrollable_frame, text="Add to Playlist", command=partial(add_to_what_playlist, id)).grid(column=1, row=index * 2, sticky="W")
        search_results_frame.tkraise()
def view_track():
    pass
def view_artist():
    pass
def populate_playlist_frame(results):
    "results = {playlist_name, track_id, title, artist_name, artist_id}"
    for widget in playlists_frame.winfo_children():
        widget.destroy()

    ttk.Label(playlist_frame.scrollable_frame, text=results[0][0], font=("Arial", 20)).grid(row=0,column=0)
    ttk.Button(playlist_frame.scrollable_frame, text="Home").grid(row=0, column=1, sticky="W")
    for index, result in enumerate(results, start=1):
        ttk.Label(playlist_frame.scrollable_frame, text=result[2], font=("Arial", 10)).grid(row=index*2,column=0, sticky="W")
        ttk.Label(playlist_frame.scrollable_frame, text=result[3], font=("Arial", 7)).grid(row=index*2+1, column=0, sticky="W")
        ttk.Button(playlist_frame.scrollable_frame, text="View Song", command=partial(view_track, (result[1]))).grid(row=index*2,column=1, sticky="W")
        ttk.Button(playlist_frame.scrollable_frame, text="View Artists", command=partial(view_artist, result[4])).grid(row=index*2+1,column=1, sticky="W")

def open_playlist(pid):
    print(f"opening playlist {pid}")
    try:
        query = """
            SELECT 
                p.name AS playlist_name,
                t.track_id,
                t.title,
                a.name,
                t.artist_id
            FROM 
                playlists p
            JOIN 
                playlistTracks pt ON p.playlist_id = pt.playlist_id
            JOIN 
                tracks t ON pt.track_id = t.track_id
            JOIN 
                artists a ON t.artist_id = a.artist_id
            WHERE 
                p.playlist_id = %s
        """
        cursor.execute(query, (pid,))
        results = cursor.fetchall()
        print(results)
        populate_playlist_frame(results)
        playlist_frame.tkraise()
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def create_new_playlist(name):
    pass

def add_to_what_playlist(track_id):
    playlists = get_playlists()

    def on_select():
        selected_index = playlist_var.get()
        if selected_index != -1:
            selected_playlist = playlists[selected_index]
            add_to_playlist(track_id, selected_playlist[0])
        popup.destroy()

    popup = tk.Toplevel()
    popup.title("Select Playlist")

    tk.Label(popup, text="Choose a playlist to add the song to:").pack(pady=10)

    # Variable to track the selected playlist
    playlist_var = tk.IntVar(value=-1)

    # Create radio buttons for each playlist
    for i, playlist in enumerate(playlists):
        tk.Radiobutton(
            popup, text=playlist[1], variable=playlist_var, value=i
        ).pack(anchor="w")

    # Add a confirmation button
    tk.Button(popup, text="Select", command=lambda: on_select()).pack(pady=10)

    popup.transient(root)  # Make the popup modal
    popup.grab_set()
    root.wait_window(popup)

def add_to_playlist(track_id, playlist_id):
    session_id = keyring.get_password("music_app", "session_id")
    if session_id:
        try:
            query = "INSERT INTO playlistTracks (playlist_id, track_id) VALUES (%s, %s)"
            cursor.execute(query, (playlist_id, track_id))
            conn.commit()
            print("playlist added")
        except mysql.connector.Error as err:
            print(f"Database error: {err}")
            return
        except Exception as e:
            print(f"Unexpected error: {e}")
            return

def populate_playlists_frame(results):
    for widget in playlists_frame.winfo_children():
        widget.destroy()

        # Add a heading
    ttk.Label(playlists_frame, text="Your Playlists", font=("Arial", 16)).grid(column=0, row=0, pady=10)
    ttk.Button(playlists_frame, text="New Playlist", command=lambda:create_new_playlist())
    # Dynamically create widgets for each playlist
    for index, (playlist_id, playlist_name) in enumerate(results, start=1):
        # Display playlist name
        ttk.Label(playlists_frame, text=playlist_name, font=("Arial", 12)).grid(column=0, row=index, sticky="W", padx=10, pady=5)
        # Add a button for actions (e.g., view or edit)
        ttk.Button(playlists_frame, text="View", command=partial(open_playlist, playlist_id)).grid(column=1, row=index, padx=10, pady=5)
    ttk.Button(playlists_frame, text="Back to Home", command=lambda:go_home()).grid(column=0, row=len(results)+1, pady=10)
def get_playlists():
    session_id = keyring.get_password("music_app", "session_id")
    try:
        user_id = validate_session(session_id)
        query = "SELECT playlist_id, name FROM Playlists WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        return results
    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return
    except Exception as e:
        print(f"Unexpected error: {e}")
        return

def go_to_playlists():
    session_id = keyring.get_password("music_app", "session_id")
    if session_id:
        playlists_frame.tkraise()
        results = get_playlists()
        populate_playlists_frame(results)

def go_home():
    session_id = keyring.get_password("music_app", "session_id")
    if session_id:
        for widget in home_frame.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.delete(0, tk.END)
        home_frame.tkraise()

def go_to_sign_in():
    session_id = keyring.get_password("music_app", "session_id")
    if session_id:
        for widget in home_frame.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.delete(0, tk.END)
        signin_frame.tkraise()

def go_to_sign_up():
    session_id = keyring.get_password("music_app", "session_id")
    if session_id:
        for widget in home_frame.winfo_children():
            if isinstance(widget, tk.Entry):
                widget.delete(0, tk.END)
        signup_frame.tkraise()

def create_playlist_frame(panel):
    frame = ttk.Frame(panel, padding="10 10 10 10")
    frame.grid(column=0, row=0, sticky="N, W, E, S")
    return frame

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

    ttk.Button(frame, text="Already have an account? Sign in here", command=lambda: go_to_sign_in()).grid(
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
    ttk.Button(frame, text="Dont have an account?", command=lambda: go_to_sign_up()).grid(column=1, row=2)

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
    search_results_frame = ScrollableFrame(root)
    search_results_frame.grid(row=0, column=0, sticky="nsew")
    playlist_frame = (ScrollableFrame(root))
    playlist_frame.grid(row=0, column=0, sticky="nsew")
    signin_frame.tkraise()

    root.mainloop()
    cursor.close()
    conn.close()
