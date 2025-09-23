# -*- coding: utf-8 -*-
"""
Internet Explorer Browser Processing Module
Handles IE index.dat files and WebCache databases
"""

import jarray
import re
from java.io import File
from java.util.logging import Level

from org.sleuthkit.datamodel import ReadContentInputStream

from phishing_detector.browser_constants import IE_FILES


class InternetExplorerProcessor:
    """Processes Internet Explorer browsers"""
    
    def __init__(self, module_instance):
        """Initialize with reference to main module instance"""
        self.module = module_instance
        
    def process_internet_explorer(self, dataSource, progressBar):
        """Process Internet Explorer browsers"""
        self.module.log(Level.INFO, "Starting Internet Explorer processing")
        
        try:
            # Verify we have necessary components
            if self.module.fileManager is None:
                self.module.log(Level.WARNING, "FileManager is None - cannot process IE files")
                return
                
            progressBar.progress("Processing IE History...")
            self.process_ie_history()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing IE Bookmarks...")
            self.process_ie_bookmarks()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing IE Cookies...")
            self.process_ie_cookies()
            
            if self.module.context.dataSourceIngestIsCancelled():
                return
            
            progressBar.progress("Processing IE WebCache...")
            self.module.log(Level.INFO, "About to process IE WebCache files")
            self.process_ie_webcache()
            
            self.module.log(Level.INFO, "Completed Internet Explorer processing")
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing Internet Explorer: " + str(e))

    def process_ie_history(self):
        """Process IE history from index.dat files"""
        try:
            index_files = self.module.fileManager.findFiles(self.module.dataSource, IE_FILES["INDEX"])
            
            for index_file in index_files:
                if not index_file.isFile() or index_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                # Parse index.dat files (would require Pasco or similar tool in real implementation)
                self.parse_ie_index_file(index_file, "Internet Explorer")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing IE history: " + str(e))

    def process_ie_bookmarks(self):
        """Process IE bookmarks from .url files"""
        try:
            bookmark_files = self.module.fileManager.findFiles(self.module.dataSource, IE_FILES["BOOKMARKS"], "Favorites")
            
            for bookmark_file in bookmark_files:
                if not bookmark_file.isFile() or bookmark_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                self.parse_ie_bookmark_file(bookmark_file, "Internet Explorer")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing IE bookmarks: " + str(e))

    def process_ie_cookies(self):
        """Process IE cookies from .txt files"""
        try:
            cookie_files = self.module.fileManager.findFiles(self.module.dataSource, IE_FILES["COOKIES"], "Cookies")
            
            for cookie_file in cookie_files:
                if not cookie_file.isFile() or cookie_file.getSize() == 0:
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                    
                self.parse_ie_cookie_file(cookie_file, "Internet Explorer")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing IE cookies: " + str(e))

    def process_ie_webcache(self):
        """Process IE WebCacheV01.dat files"""
        try:
            # Find WebCacheV01.dat files (used by IE 10+ and Edge Legacy)
            webcache_files = self.module.fileManager.findFiles(self.module.dataSource, "WebCacheV01.dat")
            self.module.log(Level.INFO, "Found " + str(len(webcache_files)) + " WebCacheV01.dat files")
            
            # Also try searching for other WebCache variations
            try:
                webcache_v24_files = self.module.fileManager.findFiles(self.module.dataSource, "WebCacheV24.dat")
                self.module.log(Level.INFO, "Found " + str(len(webcache_v24_files)) + " WebCacheV24.dat files")
                webcache_files.extend(webcache_v24_files)
            except:
                pass
                
            # Try generic WebCache pattern
            try:
                webcache_generic = self.module.fileManager.findFiles(self.module.dataSource, "WebCache*.dat")
                self.module.log(Level.INFO, "Found " + str(len(webcache_generic)) + " WebCache*.dat files")
                # Add only unique files
                for wc_file in webcache_generic:
                    if wc_file not in webcache_files:
                        webcache_files.append(wc_file)
            except:
                pass
            
            total_files = len(webcache_files)
            self.module.log(Level.INFO, "Total WebCache files to process: " + str(total_files))
            
            if total_files == 0:
                self.module.log(Level.INFO, "No WebCache files found - this is normal if IE 10+ was not used")
                return
            
            for webcache_file in webcache_files:
                if not webcache_file.isFile() or webcache_file.getSize() == 0:
                    self.module.log(Level.INFO, "Skipping WebCache file (not a file or empty): " + webcache_file.getName())
                    continue
                    
                if self.module.context.dataSourceIngestIsCancelled():
                    return
                
                # Check if it's in an IE-related directory (be more inclusive)
                file_path = webcache_file.getParentPath().lower()
                self.module.log(Level.INFO, "Found WebCache file at: " + webcache_file.getParentPath() + "/" + webcache_file.getName())
                
                # Process all WebCache files, not just IE-specific ones (could be Edge Legacy too)
                if any(ie_path in file_path for ie_path in ['internet explorer', 'iexplore', 'temporary internet files', 'inetcache', 'webcache', 'edge', 'microsoft']):
                    self.module.log(Level.INFO, "Processing IE/Edge WebCache file: " + webcache_file.getParentPath() + "/" + webcache_file.getName())
                    self.parse_ie_webcache_database(webcache_file, "Internet Explorer")
                else:
                    # Process it anyway as generic WebCache
                    self.module.log(Level.INFO, "Processing generic WebCache file: " + webcache_file.getParentPath() + "/" + webcache_file.getName())
                    self.parse_ie_webcache_database(webcache_file, "Internet Explorer/Edge")
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error processing IE WebCache: " + str(e))

    def parse_ie_index_file(self, index_file, browser_name="Internet Explorer"):
        """Parse Internet Explorer index.dat files"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " index.dat file: " + index_file.getName())
        
        try:
            # For IE index.dat parsing, we need specialized parsing
            # This is a binary format, not SQLite
            # Extract content using ReadContentInputStream
            inputStream = ReadContentInputStream(index_file)
            buffer = jarray.zeros(8192, "b")
            
            # Simple URL extraction from index.dat binary format
            # Look for URL patterns in the binary data
            content_buffer = bytearray()
            bytes_read = inputStream.read(buffer)
            
            while bytes_read != -1:
                if self.module.context.dataSourceIngestIsCancelled():
                    break
                content_buffer.extend(buffer[:bytes_read])
                bytes_read = inputStream.read(buffer)
                
                # Process buffer in chunks to avoid memory issues
                if len(content_buffer) > 65536:
                    self.extract_urls_from_ie_buffer(content_buffer[:32768], index_file, browser_name)
                    content_buffer = content_buffer[32768:]
            
            inputStream.close()
            
            # Process remaining buffer
            if len(content_buffer) > 0:
                self.extract_urls_from_ie_buffer(content_buffer, index_file, browser_name)
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " index.dat: " + str(e))

    def parse_ie_bookmark_file(self, bookmark_file, browser_name="Internet Explorer"):
        """Parse IE bookmark .url files"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " bookmark: " + bookmark_file.getName())
        
        try:
            # Read .url file content
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
            
            # Extract URL from .url file format
            # Format: [InternetShortcut]\nURL=http://example.com
            url_match = re.search(r'URL=(.+)', content, re.IGNORECASE)
            if url_match:
                url = url_match.group(1).strip()
                # Create artifact for bookmark URL
                self.module.create_url_artifact(bookmark_file, url, 0, browser_name)
                
        except Exception as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " bookmark: " + str(e))

    def parse_ie_cookie_file(self, cookie_file, browser_name="Internet Explorer"):
        """Parse IE cookie .txt files"""
        self.module.log(Level.INFO, "Found " + browser_name + " cookie file: " + cookie_file.getName())
        # IE cookie files typically don't contain URLs for phishing analysis
        # This is mainly for completeness - focus on history and bookmarks

    def extract_urls_from_ie_buffer(self, buffer, source_file, browser_name):
        """Extract URLs from IE binary buffer content with timestamp extraction"""
        try:
            # Convert buffer to string for URL pattern matching
            content = ""
            try:
                for b in buffer:
                    if b >= 32 and b < 127:  # Printable ASCII
                        content += chr(b)
                    elif b == 0:
                        content += " "
                    else:
                        content += "?"
            except:
                content = str(buffer)
            
            # Look for URL patterns (http://, https://, ftp://)
            url_patterns = [
                r'http://[^\s\x00-\x1f\x7f-\xff]+',
                r'https://[^\s\x00-\x1f\x7f-\xff]+',
                r'ftp://[^\s\x00-\x1f\x7f-\xff]+'
            ]
            
            for pattern in url_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for url in matches:
                    if self.module.context.dataSourceIngestIsCancelled():
                        break
                    # Clean up URL (remove null bytes and control chars)
                    clean_url = re.sub(r'[\x00-\x1f\x7f-\xff]', '', url)
                    if len(clean_url) > 10:  # Reasonable URL length
                        
                        # Try to extract timestamp from IE binary format
                        timestamp = self.extract_ie_timestamp_from_buffer(buffer, clean_url)
                        
                        self.module.create_url_artifact(source_file, clean_url, timestamp, browser_name)
                        
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting URLs from IE buffer: " + str(e))

    def extract_ie_timestamp_from_buffer(self, buffer, url):
        """Extract IE timestamp from binary buffer around URL location"""
        try:
            # IE index.dat uses FILETIME format (64-bit value representing 
            # 100-nanosecond intervals since January 1, 1601 UTC)
            # This is a simplified approach - look for 8-byte sequences that could be timestamps
            
            url_bytes = url.encode('ascii', 'ignore')
            content_bytes = bytes(buffer) if hasattr(buffer, '__iter__') else buffer
            
            # Find URL position in buffer
            try:
                url_pos = content_bytes.find(url_bytes)
                if url_pos == -1:
                    return 0
            except:
                return 0
            
            # Look for potential FILETIME timestamps near the URL
            # FILETIME is 8 bytes, look in reasonable range around URL
            search_start = max(0, url_pos - 100)
            search_end = min(len(content_bytes), url_pos + len(url_bytes) + 100)
            
            for i in range(search_start, search_end - 8, 4):  # Check every 4 bytes
                try:
                    # Read 8 bytes as potential FILETIME
                    filetime_bytes = content_bytes[i:i+8]
                    if len(filetime_bytes) == 8:
                        # Convert from little-endian bytes to long
                        filetime = 0
                        for j, b in enumerate(filetime_bytes):
                            if isinstance(b, str):
                                b = ord(b)
                            filetime += (b & 0xFF) << (j * 8)
                        
                        # Convert FILETIME to Unix timestamp
                        # FILETIME epoch: Jan 1, 1601; Unix epoch: Jan 1, 1970
                        # Difference: 11644473600 seconds = 116444736000000000 * 100ns
                        if filetime > 116444736000000000:  # Valid range check
                            # Convert from 100ns intervals to seconds
                            unix_timestamp = (filetime - 116444736000000000) // 10000000
                            
                            # Sanity check: timestamp should be reasonable (1990-2030)
                            if 631152000 < unix_timestamp < 1893456000:  # 1990-2030
                                return unix_timestamp
                except:
                    continue
                    
            return 0  # No valid timestamp found
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting IE timestamp: " + str(e))
            return 0

    def parse_ie_webcache_database(self, webcache_file, browser_name="Internet Explorer"):
        """Parse IE WebCacheV01.dat (ESE database format)"""
        self.module.log(Level.INFO, "Parsing " + browser_name + " WebCache database: " + webcache_file.getName())
        
        try:
            # ESE database format requires specialized parsing
            # For now, we'll do basic binary content extraction
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
                    self.extract_urls_from_webcache_buffer(content_buffer[:32768], webcache_file, browser_name)
                    content_buffer = content_buffer[32768:]
            
            inputStream.close()
            
            # Process remaining buffer
            if len(content_buffer) > 0:
                self.extract_urls_from_webcache_buffer(content_buffer, webcache_file, browser_name)
                
        except Exception as e:
            self.module.log(Level.WARNING, "Error parsing " + browser_name + " WebCache database: " + str(e))

    def extract_urls_from_webcache_buffer(self, buffer, source_file, browser_name):
        """Extract URLs from IE WebCache binary buffer"""
        try:
            # Convert buffer to string for URL pattern matching
            content = self.module.safe_buffer_to_string(buffer)
            
            # Look for URL patterns and cookie domains
            url_patterns = [
                r'http://[^\s\x00-\x1f\x7f-\xff]+',
                r'https://[^\s\x00-\x1f\x7f-\xff]+',
                r'ftp://[^\s\x00-\x1f\x7f-\xff]+',
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
                        
                        # Try to extract timestamp from WebCache binary format
                        timestamp = self.extract_webcache_timestamp_from_buffer(buffer, clean_url)
                        
                        self.module.create_url_artifact(source_file, clean_url, timestamp, browser_name)
                        
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting URLs from WebCache buffer: " + str(e))

    def extract_webcache_timestamp_from_buffer(self, buffer, url):
        """Extract timestamp from WebCache binary buffer around URL location"""
        try:
            # WebCache uses ESE database format, which includes FILETIME timestamps
            # Similar approach to index.dat but look for different patterns
            
            url_bytes = url.encode('ascii', 'ignore')
            content_bytes = bytes(buffer) if hasattr(buffer, '__iter__') else buffer
            
            # Find URL position in buffer
            try:
                url_pos = content_bytes.find(url_bytes)
                if url_pos == -1:
                    return 0
            except:
                return 0
            
            # ESE format: Look for FILETIME patterns near URL
            search_start = max(0, url_pos - 200)  # Wider search for ESE format
            search_end = min(len(content_bytes), url_pos + len(url_bytes) + 200)
            
            for i in range(search_start, search_end - 8, 2):  # Check every 2 bytes for ESE
                try:
                    # Read 8 bytes as potential FILETIME
                    filetime_bytes = content_bytes[i:i+8]
                    if len(filetime_bytes) == 8:
                        # Convert from little-endian bytes to long
                        filetime = 0
                        for j, b in enumerate(filetime_bytes):
                            if isinstance(b, str):
                                b = ord(b)
                            filetime += (b & 0xFF) << (j * 8)
                        
                        # Convert FILETIME to Unix timestamp
                        if filetime > 116444736000000000:  # Valid FILETIME range
                            unix_timestamp = (filetime - 116444736000000000) // 10000000
                            
                            # Sanity check: reasonable timestamp range (1995-2030)
                            if 788918400 < unix_timestamp < 1893456000:  # 1995-2030
                                return unix_timestamp
                except:
                    continue
                    
            return 0  # No valid timestamp found
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting WebCache timestamp: " + str(e))
            return 0