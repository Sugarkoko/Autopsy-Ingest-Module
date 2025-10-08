# -*- coding: utf-8 -*-
"""
Chromium Browser Processing Module
Handles Chrome, Edge, Brave, UC Browser, Yandex, Opera, etc.
"""

import jarray
from java.io import File
from java.sql import DriverManager, SQLException
from java.util.logging import Level

from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule import Case
from com.google.gson import JsonParser

from phishing_detector.browser_constants import CHROMIUM_BROWSERS, CHROMIUM_FILES, CHROMIUM_QUERIES


class ChromiumProcessor:
    """Processes all Chromium-based browsers"""
    
    def __init__(self, module_instance):
        """Initialize with reference to main module instance"""
        self.module = module_instance
        
    def process_all_chromium_browsers(self, dataSource, progressBar):
        """Process all Chromium-based browsers - HISTORY ONLY (no bookmarks, downloads, cookies)"""
        self.module.log(Level.INFO, "Processing Chromium-based browsers - HISTORY ONLY")
        
        try:
            for browser_name, browser_path in CHROMIUM_BROWSERS.items():
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                
                progressBar.progress("Processing " + browser_name + "...")
                self.module.log(Level.INFO, "Processing browser: " + browser_name)
                
                # Process HISTORY ONLY - skip bookmarks, downloads, cookies, logins, autofill, favicons
                self.process_chromium_history(browser_name, browser_path)
                
                # Skip all other sources to match standard web history
                self.module.log(Level.INFO, "Skipping " + browser_name + " bookmarks, downloads, cookies, logins, autofill, and favicons to match standard web history")
                
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Chromium browsers: " + str(e))

    def process_chromium_history(self, browser_name, browser_path):
        """Process Chromium browser history files"""
        try:
            history_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["HISTORY"], browser_path)
            
            for history_file in history_files:
                if not history_file.isFile() or history_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                # Check if it's in correct browser directory
                file_path = history_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_history_database(history_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " history: " + str(e))

    def process_chromium_bookmarks(self, browser_name, browser_path):
        """Process Chromium browser bookmark files"""
        try:
            bookmark_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["BOOKMARKS"], browser_path)
            
            for bookmark_file in bookmark_files:
                if not bookmark_file.isFile() or bookmark_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = bookmark_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_bookmarks_file(bookmark_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " bookmarks: " + str(e))

    def process_chromium_downloads(self, browser_name, browser_path):
        """Process Chromium browser download history"""
        try:
            # Downloads are stored in the same History database
            history_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["HISTORY"], browser_path)
            
            for history_file in history_files:
                if not history_file.isFile() or history_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = history_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_downloads_database(history_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " downloads: " + str(e))

    def process_chromium_cookies(self, browser_name, browser_path):
        """Process Chromium browser cookie files"""
        try:
            cookie_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["COOKIES"], browser_path)
            
            for cookie_file in cookie_files:
                if not cookie_file.isFile() or cookie_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = cookie_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_cookies_database(cookie_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " cookies: " + str(e))

    def process_chromium_logins(self, browser_name, browser_path):
        """Process Chromium browser login data"""
        try:
            login_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["LOGIN_DATA"], browser_path)
            
            for login_file in login_files:
                if not login_file.isFile() or login_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = login_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_logins_database(login_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " logins: " + str(e))

    def process_chromium_autofill(self, browser_name, browser_path):
        """Process Chromium browser autofill data"""
        try:
            webdata_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["WEB_DATA"], browser_path)
            
            for webdata_file in webdata_files:
                if not webdata_file.isFile() or webdata_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = webdata_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_autofill_database(webdata_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " autofill: " + str(e))

    def process_chromium_favicons(self, browser_name, browser_path):
        """Process Chromium browser favicon data"""
        try:
            favicon_files = self.module.fileManager.findFiles(self.module.dataSource, CHROMIUM_FILES["FAVICONS"], browser_path)
            
            for favicon_file in favicon_files:
                if not favicon_file.isFile() or favicon_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = favicon_file.getParentPath().lower()
                if any(browser.lower() in file_path for browser in browser_name.split()):
                    self.parse_chromium_favicons_database(favicon_file, browser_name)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " favicons: " + str(e))

    def parse_chromium_history_database(self, history_file, browser_name):
        """Parse Chromium History SQLite database for browsing history"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " history file: " + history_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(history_file.getId()) + "_" + browser_name.replace(" ", "_") + "_history.db"
            
            ContentUtils.writeToFile(history_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            stmt = dbConn.createStatement()
            
            resultSet = stmt.executeQuery(CHROMIUM_QUERIES["HISTORY"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                url = resultSet.getString("url")
                title = resultSet.getString("title") if resultSet.getString("title") else ""
                visit_time = resultSet.getLong("visit_time")
                last_visit_time = resultSet.getLong("last_visit_time")
                visit_count = resultSet.getInt("visit_count")
                
                # Convert Chrome timestamp to Unix timestamp (microseconds since Jan 1, 1601)
                unix_timestamp = (visit_time - 11644473600000000) / 1000000 if visit_time > 0 else 0
                
                # Create artifact for this URL
                self.module.create_url_artifact(history_file, url, unix_timestamp, browser_name)
            
            stmt.close()
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " history database: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " history: " + str(e))

    def parse_chromium_bookmarks_file(self, bookmark_file, browser_name):
        """Parse Chromium bookmarks JSON file"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " bookmarks: " + bookmark_file.getName())
        
        try:
            # Read the JSON content
            inputStream = ReadContentInputStream(bookmark_file)
            content = ""
            buffer = jarray.zeros(1024, "b")
            bytes_read = inputStream.read(buffer)
            
            while bytes_read != -1:
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                content += self.module.safe_buffer_to_string(buffer[:bytes_read])
                bytes_read = inputStream.read(buffer)
            
            inputStream.close()
            
            # Parse JSON
            parser = JsonParser()
            root = parser.parse(content).getAsJsonObject()
            
            # Extract bookmarks from the JSON structure
            if root.has("roots"):
                roots = root.get("roots").getAsJsonObject()
                for key in ["bookmark_bar", "other", "synced"]:
                    if roots.has(key):
                        folder = roots.get(key).getAsJsonObject()
                        self.extract_bookmarks_from_folder(folder, bookmark_file, browser_name)
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " bookmarks: " + str(e))

    def extract_bookmarks_from_folder(self, folder, source_file, browser_name):
        """Recursively extract bookmarks from JSON folder structure"""
        try:
            if folder.has("children"):
                children = folder.get("children").getAsJsonArray()
                
                for i in range(children.size()):
                    if self.module.context.dataSourceIngestIsCancelled():
                        break
                        
                    child = children.get(i).getAsJsonObject()
                    
                    if child.has("type"):
                        type_val = child.get("type").getAsString()
                        
                        if type_val == "url" and child.has("url"):
                            url = child.get("url").getAsString()
                            name = child.get("name").getAsString() if child.has("name") else ""
                            date_added = 0
                            
                            if child.has("date_added"):
                                # Chrome timestamp to Unix timestamp
                                chrome_time = child.get("date_added").getAsLong()
                                date_added = (chrome_time - 11644473600000000) / 1000000 if chrome_time > 0 else 0
                            
                            self.module.create_url_artifact(source_file, url, date_added, browser_name)
                        
                        elif type_val == "folder":
                            # Recursively process folder
                            self.extract_bookmarks_from_folder(child, source_file, browser_name)
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting bookmarks from folder: " + str(e))

    def parse_chromium_downloads_database(self, history_file, browser_name):
        """Parse Chromium downloads from History database"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " downloads: " + history_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(history_file.getId()) + "_" + browser_name.replace(" ", "_") + "_downloads.db"
            
            ContentUtils.writeToFile(history_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            stmt = dbConn.createStatement()
            
            # Check if this is Chrome v30+ (uses different query)
            is_v30_plus = self.is_chrome_v30_plus(temp_db_path)
            query = CHROMIUM_QUERIES["DOWNLOADS_V30"] if is_v30_plus else CHROMIUM_QUERIES["DOWNLOADS"]
            
            resultSet = stmt.executeQuery(query)
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                url = resultSet.getString("url")
                full_path = resultSet.getString("full_path") if resultSet.getString("full_path") else ""
                start_time = resultSet.getLong("start_time")
                
                # Convert Chrome timestamp to Unix timestamp
                unix_timestamp = (start_time - 11644473600000000) / 1000000 if start_time > 0 else 0
                
                # Create artifact for download URL
                self.module.create_url_artifact(history_file, url, unix_timestamp, browser_name)
            
            stmt.close()
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " downloads: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " downloads: " + str(e))

    def is_chrome_v30_plus(self, db_path):
        """Check if Chrome database is version 30 or higher"""
        try:
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + db_path)
            stmt = dbConn.createStatement()
            
            # Check for presence of downloads_url_chains table (v30+)
            resultSet = stmt.executeQuery("SELECT name FROM sqlite_master WHERE type='table' AND name='downloads_url_chains'")
            has_chains_table = resultSet.next()
            
            stmt.close()
            dbConn.close()
            
            return has_chains_table
            
        except Exception:
            return False

    def parse_chromium_cookies_database(self, cookie_file, browser_name):
        """Parse Chromium cookies database - placeholder for additional functionality"""
        self.module.log(Level.INFO, "Found " + browser_name + " cookies database: " + cookie_file.getName())
        # Cookies don't typically contain URLs for phishing analysis
        # This is mainly for completeness - focus on history and bookmarks

    def parse_chromium_logins_database(self, login_file, browser_name):
        """Parse Chromium logins database"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " logins: " + login_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(login_file.getId()) + "_" + browser_name.replace(" ", "_") + "_logins.db"
            
            ContentUtils.writeToFile(login_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            stmt = dbConn.createStatement()
            
            resultSet = stmt.executeQuery(CHROMIUM_QUERIES["LOGINS"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                origin_url = resultSet.getString("origin_url")
                date_created = resultSet.getLong("date_created")
                
                # Convert Chrome timestamp to Unix timestamp
                unix_timestamp = (date_created - 11644473600000000) / 1000000 if date_created > 0 else 0
                
                # Create artifact for login URL
                self.module.create_url_artifact(login_file, origin_url, unix_timestamp, browser_name)
            
            stmt.close()
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " logins: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " logins: " + str(e))

    def parse_chromium_autofill_database(self, webdata_file, browser_name):
        """Parse Chromium autofill database - placeholder for additional functionality"""
        self.module.log(Level.INFO, "Found " + browser_name + " autofill database: " + webdata_file.getName())
        # Autofill data typically doesn't contain URLs for phishing analysis
        # This is mainly for completeness - focus on history and bookmarks

    def parse_chromium_favicons_database(self, favicon_file, browser_name):
        """Parse Chromium favicons database"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " favicons: " + favicon_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(favicon_file.getId()) + "_" + browser_name.replace(" ", "_") + "_favicons.db"
            
            ContentUtils.writeToFile(favicon_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            stmt = dbConn.createStatement()
            
            resultSet = stmt.executeQuery(CHROMIUM_QUERIES["FAVICONS"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                page_url = resultSet.getString("page_url")
                last_updated = resultSet.getLong("last_updated")
                
                # Convert Chrome timestamp to Unix timestamp
                unix_timestamp = (last_updated - 11644473600000000) / 1000000 if last_updated > 0 else 0
                
                # Create artifact for favicon URL
                self.module.create_url_artifact(favicon_file, page_url, unix_timestamp, browser_name)
            
            stmt.close()
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " favicons: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " favicons: " + str(e))