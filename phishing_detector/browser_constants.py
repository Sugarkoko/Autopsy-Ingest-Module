# -*- coding: utf-8 -*-
"""
Browser Constants and Database Queries for Phishing Detection Module
Contains all browser patterns, database file names, and SQL queries
"""

# Browser definitions based on Autopsy patterns
CHROMIUM_BROWSERS = {
    "Google Chrome": "Chrome/User Data",
    "Microsoft Edge": "Microsoft/Edge/User Data",
    "Brave": "BraveSoftware/Brave-Browser/User Data",
    "UC Browser": "UCBrowser/User Data",
    "Yandex": "YandexBrowser/User Data",
    "Opera": "Opera Software/Opera Stable",
    "SalamWeb": "SalamWeb/User Data",
    "Chromium": "Chromium/User Data"
}

# Database file patterns
CHROMIUM_FILES = {
    "HISTORY": "History",
    "BOOKMARKS": "Bookmarks",
    "COOKIES": "Cookies",
    "LOGIN_DATA": "Login Data",
    "WEB_DATA": "Web Data",
    "FAVICONS": "Favicons",
    "PREFERENCES": "Preferences",
    "SECURE_PREFERENCES": "Secure Preferences"
}

FIREFOX_FILES = {
    "PLACES": "places.sqlite",
    "COOKIES": "cookies.sqlite", 
    "FORMHISTORY": "formhistory.sqlite",
    "PROFILES": "profiles.ini"
}

IE_FILES = {
    "INDEX": "index.dat",
    "BOOKMARKS": "%.url",
    "COOKIES": "%.txt"
}

# SQL queries based on Autopsy patterns
CHROMIUM_QUERIES = {
    "HISTORY": """SELECT urls.url, urls.title, urls.visit_count, urls.typed_count, 
                 last_visit_time, urls.hidden, visits.visit_time, 
                 (SELECT urls.url FROM urls WHERE urls.id=visits.url) AS from_visit 
                 FROM urls, visits WHERE urls.id = visits.url""",
    
    "DOWNLOADS": """SELECT full_path, url, start_time, received_bytes FROM downloads""",
    
    "DOWNLOADS_V30": """SELECT current_path AS full_path, url, start_time, received_bytes 
                       FROM downloads, downloads_url_chains 
                       WHERE downloads.id=downloads_url_chains.id""",
    
    "COOKIES": "SELECT name, value, host_key, expires_utc, last_access_utc, creation_utc FROM cookies",
    
    "LOGINS": "SELECT origin_url, username_value, date_created, signon_realm from logins",
    
    "AUTOFILL": """SELECT name, value, count, date_created FROM autofill, autofill_dates 
                  WHERE autofill.pair_id = autofill_dates.pair_id""",
    
    "FAVICONS": """SELECT page_url, last_updated, last_requested FROM icon_mapping, favicon_bitmaps 
                  WHERE icon_mapping.icon_id = favicon_bitmaps.icon_id"""
}

FIREFOX_QUERIES = {
    "HISTORY": """SELECT moz_historyvisits.id, url, title, visit_count, 
                 (visit_date/1000000) AS visit_date, from_visit,
                 (SELECT url FROM moz_historyvisits history, moz_places places 
                  WHERE history.id = moz_historyvisits.from_visit 
                  AND history.place_id = places.id) as ref 
                 FROM moz_places, moz_historyvisits 
                 WHERE moz_places.id = moz_historyvisits.place_id AND hidden = 0""",
    
    "BOOKMARKS": """SELECT fk, moz_bookmarks.title, url, 
                   (moz_bookmarks.dateAdded/1000000) AS dateAdded 
                   FROM moz_bookmarks INNER JOIN moz_places 
                   ON moz_bookmarks.fk=moz_places.id""",
    
    "COOKIES": """SELECT name, value, host, expiry, 
                 (lastAccessed/1000000) AS lastAccessed, 
                 (creationTime/1000000) AS creationTime FROM moz_cookies""",
    
    "DOWNLOADS_PRE24": """SELECT name, source, target, startTime, endTime, state, referrer 
                         FROM moz_downloads WHERE target IS NOT NULL""",
    
    "DOWNLOADS_V24": """SELECT name, url, target, startTime, lastModified 
                       FROM moz_downloads""",
    
    "FORMHISTORY": "SELECT fieldname, value FROM moz_formhistory",
    
    "FORMHISTORY_V64": "SELECT fieldname, value, timesUsed, firstUsed, lastUsed FROM moz_formhistory"
}

SAFARI_QUERIES = {
    "HISTORY": """SELECT url, title, visit_time, visit_count, load_successful
                 FROM history_visits 
                 LEFT JOIN history_items ON history_visits.history_item = history_items.id 
                 ORDER BY visit_time DESC"""
}