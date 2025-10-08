# -*- coding: utf-8 -*-
"""
Safari and Edge Legacy Browser Processing Module
Handles Safari History.db and Edge Legacy WebCache files  
"""

import jarray
import re
from java.io import File
from java.sql import DriverManager, SQLException
from java.util.logging import Level

from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.casemodule import Case

from phishing_detector.browser_constants import SAFARI_QUERIES


class SafariEdgeProcessor:
    """Processes Safari and Edge Legacy browsers"""
    
    def __init__(self, module_instance):
        """Initialize with reference to main module instance"""
        self.module = module_instance
        
    def process_safari_browsers(self, dataSource, progressBar):
        """Process Safari browsers - HISTORY ONLY (primarily on macOS/iOS but may appear on Windows)"""
        self.module.log(Level.INFO, "Processing Safari browsers - HISTORY ONLY")
        
        try:
            # Safari uses various file formats, mainly plist and sqlite
            progressBar.progress("Processing Safari History...")
            self.process_safari_history()
            
            # Skip bookmarks to match standard web history
            self.module.log(Level.INFO, "Skipping Safari bookmarks to match standard web history")
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Safari: " + str(e))

    def process_safari_history(self):
        """Process Safari history files"""
        try:
            # Look for Safari history databases
            safari_files = self.module.fileManager.findFiles(self.module.dataSource, "History.db", "Safari")
            
            for safari_file in safari_files:
                if not safari_file.isFile() or safari_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                self.parse_safari_history_database(safari_file, "Safari")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Safari history: " + str(e))

    def process_edge_legacy(self, dataSource, progressBar):
        """Process Microsoft Edge Legacy (pre-Chromium) - HISTORY ONLY"""
        self.module.log(Level.INFO, "Processing Microsoft Edge Legacy - HISTORY ONLY")
        
        try:
            # Edge Legacy uses ESE databases
            progressBar.progress("Processing Edge Legacy...")
            edge_files = self.module.fileManager.findFiles(self.module.dataSource, "WebCacheV01.dat")
            self.module.log(Level.INFO, "Found " + str(len(edge_files)) + " WebCacheV01.dat files for Edge Legacy")
            
            for edge_file in edge_files:
                if not edge_file.isFile() or edge_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                file_path = edge_file.getParentPath().lower()
                self.module.log(Level.INFO, "Checking Edge file at: " + edge_file.getParentPath())
                
                # Be more inclusive - Edge Legacy files might be in various locations
                if any(edge_indicator in file_path for edge_indicator in ['microsoft', 'edge', 'microsoftedge']):
                    self.module.log(Level.INFO, "Processing Edge Legacy WebCache: " + edge_file.getParentPath() + "/" + edge_file.getName())
                    self.parse_edge_webcache_database(edge_file, "Edge Legacy")
                else:
                    # Still process as potential Edge Legacy if we haven't processed it as IE
                    self.module.log(Level.INFO, "Processing potential Edge Legacy file: " + edge_file.getParentPath() + "/" + edge_file.getName())
                    self.parse_edge_webcache_database(edge_file, "Edge Legacy")
            
            # Edge Legacy only processes WebCache (history) - no bookmarks or other sources
            self.module.log(Level.INFO, "Edge Legacy only processes WebCache history - no additional sources to skip")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Edge Legacy: " + str(e))

    def parse_safari_history_database(self, history_file, browser_name="Safari"):
        """Parse Safari History.db database"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " history database: " + history_file.getName())
        
        try:
            # Extract database to temp location
            temp_db_path = self.module.currentCase.getTempDirectory() + File.separator + \
                          str(history_file.getId()) + "_" + browser_name.replace(" ", "_") + "_history.db"
            
            ContentUtils.writeToFile(history_file, File(temp_db_path))
            
            # Connect to SQLite database
            dbConn = DriverManager.getConnection("jdbc:sqlite:" + temp_db_path)
            stmt = dbConn.createStatement()
            
            # Parse Safari history
            resultSet = stmt.executeQuery(SAFARI_QUERIES["HISTORY"])
            
            while resultSet.next():
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                    
                url = resultSet.getString("url")
                title = resultSet.getString("title") if resultSet.getString("title") else ""
                visit_time = resultSet.getDouble("visit_time")
                visit_count = resultSet.getInt("visit_count")
                
                # Safari timestamps are seconds since 2001-01-01 (Mac epoch)
                # Convert to Unix timestamp: add seconds between 1970 and 2001
                unix_timestamp = visit_time + 978307200 if visit_time > 0 else 0
                
                self.module.create_url_artifact(history_file, url, unix_timestamp, browser_name)
            
            stmt.close()
            dbConn.close()
            
            # Clean up temp file
            File(temp_db_path).delete()
            
        except SQLException as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " history database: " + str(e))
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing " + browser_name + " history: " + str(e))

    def parse_safari_bookmarks_plist(self, bookmarks_file, browser_name="Safari"):
        """Parse Safari Bookmarks.plist file"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " bookmarks plist: " + bookmarks_file.getName())
        
        try:
            # Read plist content as binary
            inputStream = ReadContentInputStream(bookmarks_file)
            content = ""
            buffer = jarray.zeros(1024, "b")
            bytes_read = inputStream.read(buffer)
            
            while bytes_read != -1:
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                content += self.module.safe_buffer_to_string(buffer[:bytes_read])
                bytes_read = inputStream.read(buffer)
            
            inputStream.close()
            
            # Extract URLs from plist content using regex
            url_pattern = r'<string>(https?://[^<]+)</string>'
            title_pattern = r'<key>Title</key>\s*<string>([^<]*)</string>'
            
            urls = re.findall(url_pattern, content)
            titles = re.findall(title_pattern, content)
            
            # Match URLs with titles (best effort)
            for i, url in enumerate(urls):
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                title = titles[i] if i < len(titles) else ""
                self.module.create_url_artifact(bookmarks_file, url, 0, browser_name)
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " bookmarks plist: " + str(e))

    def parse_edge_webcache_database(self, webcache_file, browser_name="Edge Legacy"):
        """Parse Edge Legacy WebCacheV01.dat database"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " WebCache database: " + webcache_file.getName())
        
        try:
            # Edge Legacy uses ESE database format (like IE)
            # Use similar approach to IE WebCache parsing
            inputStream = ReadContentInputStream(webcache_file)
            buffer = jarray.zeros(8192, "b")
            
            content_buffer = bytearray()
            bytes_read = inputStream.read(buffer)
            
            while bytes_read != -1:
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                content_buffer.extend(buffer[:bytes_read])
                bytes_read = inputStream.read(buffer)
                
                # Process buffer in chunks
                if len(content_buffer) > 65536:
                    self.extract_urls_from_edge_buffer(content_buffer[:32768], webcache_file, browser_name)
                    content_buffer = content_buffer[32768:]
            
            inputStream.close()
            
            # Process remaining buffer
            if len(content_buffer) > 0:
                self.extract_urls_from_edge_buffer(content_buffer, webcache_file, browser_name)
                
        except Exception as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " WebCache database: " + str(e))

    def extract_urls_from_edge_buffer(self, buffer, source_file, browser_name):
        """Extract URLs from Edge Legacy buffer content"""
        try:
            # Convert buffer to string for URL pattern matching
            content = self.module.safe_buffer_to_string(buffer)
            
            # Look for URL patterns
            url_patterns = [
                r'http://[^\s\x00-\x1f\x7f-\xff]+',
                r'https://[^\s\x00-\x1f\x7f-\xff]+',
                r'microsoft-edge:[^\s\x00-\x1f\x7f-\xff]+',
                r'www\.[a-zA-Z0-9-]+\.[a-zA-Z]{2,}[^\s\x00-\x1f]*'
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for url in matches:
                    if self.module.context.dataSourceIngestIsCancelled():
                        break
                    # Clean up URL
                    clean_url = re.sub(r'[\x00-\x1f\x7f-\xff]', '', url)
                    if len(clean_url) > 10:
                        # Add http:// prefix for www. URLs
                        if clean_url.startswith('www.'):
                            clean_url = 'http://' + clean_url
                        self.module.create_url_artifact(source_file, clean_url, 0, browser_name)
                        
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting URLs from Edge buffer: " + str(e))