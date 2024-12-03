from platform import release

import spotipy
from spotipy.oauth2 import SpotifyClientCredentials
import mysql.connector

# Spotify API credentials
SPOTIFY_CLIENT_ID = 'your_client_id'
SPOTIFY_CLIENT_SECRET = 'your_client_secret'

# Database credentials
DB_HOST = 'localhost'
DB_USER = 'your_username'
DB_PASSWORD = 'your_password'
DB_NAME = 'music_db'

# Connect to Spotify API
sp = spotipy.Spotify(auth_manager=SpotifyClientCredentials(
    client_id="dea4914974684bfb8d669ab4a488a7eb",
    client_secret="6e367e4ba39644a2bde8561d221ed2d4"
))

# Connect to the database
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Lushane27#01",
    database="music_db"
)
cursor = db.cursor()


# Function to save artist data
def save_artist(artist):
    print(f"saving artist {artist['name']}")
    sql = """
        INSERT INTO Artists (artist_id, name, popularity)
        VALUES (%s, %s, %s)
        ON DUPLICATE KEY UPDATE name = VALUES(name), popularity = VALUES(popularity);
    """
    cursor.execute(sql, (artist['id'], artist['name'], artist['popularity']))
    db.commit()


# Function to save album data
def save_album(album, artist_id, release_date, popularity):
    print(f"saving album {album['name']}")
    sql = """
        INSERT INTO Albums (album_id, title, release_date, artist_id, popularity)
        VALUES (%s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE title = VALUES(title), release_date = VALUES(release_date), popularity = VALUES(popularity);
    """
    # Map album['name'] to the 'title' column in the database
    cursor.execute(sql, (album['id'], album['name'], release_date, artist_id, popularity))
    db.commit()


# Function to save track data
def save_track(track, album_id, release_date, popularity, artist_id):
    print(f"saving track {track['name']}")
    sql = """
        INSERT INTO Tracks (track_id, title, album_id, artist_id, release_date, popularity)
        VALUES (%s, %s, %s, %s, %s, %s)
        ON DUPLICATE KEY UPDATE title = VALUES(title), popularity = VALUES(popularity), release_date = VALUES(release_date);
    """
    cursor.execute(sql, (track['id'], track['name'], album_id, artist_id, release_date, popularity))
    db.commit()


# Fetch top 100 artists
def fetch_top_artists():
    results = sp.search(q='genre:pop', type='artist', limit=50)
    artists = results['artists']['items']

    # Process each artist
    for artist in artists:
        save_artist(artist)
        popularity = artist['popularity']
        fetch_albums(artist['id'], popularity)


# Fetch albums for an artist
def fetch_albums(artist_id, popularity):
    results = sp.artist_albums(artist_id, album_type='album', limit=50)
    albums = results['items']

    # Process each album
    for album in albums:
        release_date_precision = album['release_date_precision']
        release_date = album['release_date']
        if release_date_precision == "month":
            release_date = f"{release_date}-01"
        elif release_date_precision == "year":
            release_date = f"{release_date}-01-01"
        save_album(album, artist_id, release_date, popularity)
        fetch_tracks(album['id'], artist_id, release_date, popularity)


# Fetch tracks for an album
def fetch_tracks(album_id,artist_id, release_date, popularity):
    results = sp.album_tracks(album_id, limit=50)
    tracks = results['items']

    # Process each track
    for track in tracks:
        save_track(track, album_id, release_date, popularity, artist_id)


# Main execution
if __name__ == '__main__':
    try:
        fetch_top_artists()
        print("Data saved successfully.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        db.close()
