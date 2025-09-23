# -*- coding: utf-8 -*-
"""
Firefox Browser Processing Module  
Handles Mozilla Firefox browsers and places.sqlite database parsing
"""

from java.io import File
from java.sql import DriverManager, SQLException
from java.util.logging import Level

from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule import Case

from phishing_detector.browser_constants import FIREFOX_FILES, FIREFOX_QUERIES


class FirefoxProcessor:
    """Processes Mozilla Firefox browsers"""
    
    def __init__(self, module_instance):
        """Initialize with reference to main module instance"""
        self.module = module_instance
        
    def process_all_firefox_browsers(self, dataSource, progressBar):
        """Process Mozilla Firefox browsers comprehensively"""
        self.module.log(Level.INFO, "Processing Mozilla Firefox browsers")
        
        try:
            progressBar.progress("Processing Firefox History...")
            self.process_firefox_history()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing Firefox Bookmarks...")
            self.process_firefox_bookmarks()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing Firefox Downloads...")
            self.process_firefox_downloads()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing Firefox Cookies...")
            self.process_firefox_cookies()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing Firefox Form History...")
            self.process_firefox_form_history()
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Firefox browsers: " + str(e))

    def process_firefox_history(self):
        """Process Firefox history from places.sqlite"""
        try:
            places_files = self.module.fileManager.findFiles(self.module.dataSource, FIREFOX_FILES["PLACES"], "Firefox")
            
            for places_file in places_files:
                if not places_file.isFile() or places_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                # Check if it's in a Firefox directory
                file_path = places_file.getParentPath().lower()
                if 'firefox' in file_path:
                    self.parse_firefox_places_database(places_file, "Firefox")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Firefox history: " + str(e))

    def process_firefox_bookmarks(self):
        """Process Firefox bookmarks from places.sqlite"""
        try:
            places_files = self.module.fileManager.findFiles(self.module.dataSource, FIREFOX_FILES["PLACES"], "Firefox")
            
            for places_file in places_files:
                if not places_file.isFile() or places_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = places_file.getParentPath().lower()
                if 'firefox' in file_path:
                    self.parse_firefox_places_database(places_file, "Firefox")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Firefox bookmarks: " + str(e))

    def process_firefox_downloads(self):
        """Process Firefox downloads from places.sqlite"""
        try:
            places_files = self.module.fileManager.findFiles(self.module.dataSource, FIREFOX_FILES["PLACES"], "Firefox")
            
            for places_file in places_files:
                if not places_file.isFile() or places_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = places_file.getParentPath().lower()
                if 'firefox' in file_path:
                    self.parse_firefox_places_database(places_file, "Firefox")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Firefox downloads: " + str(e))

    def process_firefox_cookies(self):
        """Process Firefox cookies from cookies.sqlite"""
        try:
            cookie_files = self.module.fileManager.findFiles(self.module.dataSource, FIREFOX_FILES["COOKIES"], "Firefox")
            
            for cookie_file in cookie_files:
                if not cookie_file.isFile() or cookie_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = cookie_file.getParentPath().lower()
                if 'firefox' in file_path:
                    # Note: Firefox cookies don't typically contain URLs for phishing analysis
                    # This is mainly for completeness - focus on history and bookmarks
                    self.module.log(Level.INFO, "Found Firefox cookies file: " + cookie_file.getName())
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Firefox cookies: " + str(e))

    def process_firefox_form_history(self):
        """Process Firefox form history from formhistory.sqlite"""
        try:
            form_files = self.module.fileManager.findFiles(self.module.dataSource, FIREFOX_FILES["FORMHISTORY"], "Firefox")
            
            for form_file in form_files:
                if not form_file.isFile() or form_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = form_file.getParentPath().lower()
                if 'firefox' in file_path:
                    # Note: Firefox form history typically doesn't contain URLs for phishing analysis
                    # This is mainly for completeness - focus on history and bookmarks  
                    self.module.log(Level.INFO, "Found Firefox form history file: " + form_file.getName())
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Firefox form history: " + str(e))

    def parse_firefox_places_database(self, places_file, browser_name="Firefox"):
        """Parse Firefox places.sqlite database for history and bookmarks"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " places database: " + places_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(places_file.getId()) + "_" + browser_name.replace(" ", "_") + "_places.db"
            
            ContentUtils.writeToFile(places_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            
            # Parse history
            self.parse_firefox_history_from_db(dbConn, places_file, browser_name)
            
            # Parse bookmarks
            self.parse_firefox_bookmarks_from_db(dbConn, places_file, browser_name)
            
            # Parse downloads if downloads table exists
            self.parse_firefox_downloads_from_places(dbConn, places_file, browser_name)
            
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " places database: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " places: " + str(e))

    def parse_firefox_history_from_db(self, db_conn, places_file, browser_name):
        """Parse Firefox history from places database"""
        try:
            stmt = db_conn.createStatement()
            resultSet = stmt.executeQuery(FIREFOX_QUERIES["HISTORY"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                url = resultSet.getString("url")
                title = resultSet.getString("title") if resultSet.getString("title") else ""
                visit_date = resultSet.getLong("visit_date")
                visit_count = resultSet.getInt("visit_count")
                
                # Firefox timestamps are already in seconds since Unix epoch (divided by 1000000 in query)
                unix_timestamp = visit_date if visit_date > 0 else 0
                
                self.module.create_url_artifact(places_file, url, unix_timestamp, browser_name)
            
            stmt.close()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " history: " + str(e))

    def parse_firefox_bookmarks_from_db(self, db_conn, places_file, browser_name):
        """Parse Firefox bookmarks from places database"""
        try:
            stmt = db_conn.createStatement()
            resultSet = stmt.executeQuery(FIREFOX_QUERIES["BOOKMARKS"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                url = resultSet.getString("url")
                title = resultSet.getString("title") if resultSet.getString("title") else ""
                dateAdded = resultSet.getLong("dateAdded")
                
                # Firefox timestamps are already in seconds since Unix epoch (divided by 1000000 in query)
                unix_timestamp = dateAdded if dateAdded > 0 else 0
                
                self.module.create_url_artifact(places_file, url, unix_timestamp, browser_name)
            
            stmt.close()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " bookmarks: " + str(e))

    def parse_firefox_downloads_from_places(self, db_conn, places_file, browser_name):
        """Parse Firefox downloads from places database (if downloads table exists)"""
        try:
            # Check if downloads table exists
            stmt = db_conn.createStatement()
            metadata = db_conn.getMetaData()
            tables = metadata.getTables(None, None, "moz_downloads", None)
            
            if tables.next():
                # Downloads table exists, parse it
                resultSet = stmt.executeQuery(FIREFOX_QUERIES["DOWNLOADS_PRE24"])
                
                while resultSet.next():
                    if self.module.context.dataSourceIngestIsCancelled():
                        break
                        
                    source = resultSet.getString("source")
                    target = resultSet.getString("target") if resultSet.getString("target") else ""
                    start_time = resultSet.getLong("startTime")
                    
                    # Firefox timestamps are in microseconds since Unix epoch
                    unix_timestamp = start_time / 1000000 if start_time > 0 else 0
                    
                    self.module.create_url_artifact(places_file, source, unix_timestamp, browser_name)
            
            stmt.close()
            
        except SQLException as e:
            self.module.log(Level.INFO, browser_name + " downloads table not found or error parsing: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " downloads: " + str(e))

    def parse_firefox_downloads_database(self, downloads_file, browser_name="Firefox"):
        """Parse Firefox downloads.sqlite database (separate file in newer versions)"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " downloads database: " + downloads_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(downloads_file.getId()) + "_" + browser_name.replace(" ", "_") + "_downloads.db"
            
            ContentUtils.writeToFile(downloads_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            stmt = dbConn.createStatement()
            
            # Use the downloads query for Firefox
            resultSet = stmt.executeQuery(FIREFOX_QUERIES["DOWNLOADS_V24"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                url = resultSet.getString("url")
                target = resultSet.getString("target") if resultSet.getString("target") else ""
                start_time = resultSet.getLong("startTime")
                
                # Firefox timestamps are in microseconds since Unix epoch
                unix_timestamp = start_time / 1000000 if start_time > 0 else 0
                
                self.module.create_url_artifact(downloads_file, url, unix_timestamp, browser_name)
            
            stmt.close()
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " downloads database: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " downloads: " + str(e))