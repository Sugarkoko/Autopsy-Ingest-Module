# -*- coding: utf-8 -*-
"""
Autopsy Ingest Module for Web URL Extraction and Phishing Detection
Main module file 

Supported browsers and sources:
- Chromium-based: Chrome, Edge, Brave, UC Browser, Yandex, Opera, SalamWeb
- Mozilla Firefox (all versions)
- Internet Explorer
- Safari
- URL sources: History, Bookmarks, Downloads, Cookies, Form Data, Cache, Favicons, Login Data
"""

import jarray
import inspect
import os
import sys
import json
import time
from java.lang import Class
from java.lang import System
from java.sql  import DriverManager, SQLException
from java.util.logging import Level
from java.io import File
from java.io import BufferedReader
from java.io import InputStreamReader
from java.util import Arrays
from java.util import HashSet
from java.net import URLDecoder
from org.apache.commons.io import FilenameUtils
from com.google.gson import JsonParser
from com.google.gson import JsonObject
from com.google.gson import JsonArray
from com.google.gson import JsonElement

from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.datamodel import TskData
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest.IngestModule import IngestModuleException
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettings
from org.sleuthkit.autopsy.ingest import IngestModuleIngestJobSettingsPanel
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.ingest import ModuleDataEvent
from org.sleuthkit.autopsy.coreutils import Logger
from org.sleuthkit.autopsy.coreutils import PlatformUtil
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager
from org.sleuthkit.autopsy.datamodel import ContentUtils
from org.sleuthkit.autopsy.coreutils import NetworkUtils

# Ensure this directory is on sys.path so sibling 'phishing_detector' package can be imported
try:
    base_dir = os.path.dirname(__file__)
    if base_dir and base_dir not in sys.path:
        sys.path.insert(0, base_dir)
except Exception:
    pass

# Import our modular browser processors
# Use absolute imports so this works when Autopsy loads this file as a top-level module
from phishing_detector.chromium_processor import ChromiumProcessor
from phishing_detector.firefox_processor import FirefoxProcessor
from phishing_detector.ie_processor import InternetExplorerProcessor
from phishing_detector.safari_edge_processor import SafariEdgeProcessor
from phishing_detector.artifact_creator import ArtifactCreator
from phishing_detector.report_generator import ReportGenerator


class UrlPhishingIngestModuleFactory(IngestModuleFactoryAdapter):
    """Factory for creating comprehensive URL Phishing ingest modules"""
    
    moduleName = "Comprehensive URL Phishing Extractor"

    def getModuleDisplayName(self):
        return self.moduleName

    def getModuleDescription(self):
        return "Extracts web URLs from ALL browser sources (Chrome, Firefox, IE, Safari, Edge, Brave, etc.) and all URL types (history, bookmarks, downloads, cookies, form data, cache) to create comprehensive 'URL Phishing Analysis' artifacts for advanced phishing detection."

    def getModuleVersionNumber(self):
        return "2.0"

    def isDataSourceIngestModuleFactory(self):
        return True

    def createDataSourceIngestModule(self, ingestOptions):
        return UrlPhishingIngestModule()


class UrlPhishingIngestModule(DataSourceIngestModule):
    """Comprehensive ingest module for extracting URLs from browser HISTORY ONLY - VERSION 2.2"""
    
    _logger = Logger.getLogger(UrlPhishingIngestModuleFactory.moduleName)

    def log(self, level, msg):
        self._logger.logp(level, self.__class__.__name__, inspect.stack()[1][3], msg)
    
    def safe_buffer_to_string(self, buffer):
        """Safely convert buffer to string in Jython"""
        try:
            if hasattr(buffer, 'tostring'):
                return buffer.tostring()
            else:
                result = ""
                for b in buffer:
                    if isinstance(b, int) and 32 <= b < 127:
                        result += chr(b)
                    else:
                        result += "?"
                return result
        except Exception:
            return str(buffer)

    def __init__(self):
        self.context = None
        self.local_settings = None
        self.art_url_history = None
        self.dataSource = None
        self.currentCase = None
        self.fileManager = None
        # Initialize counters for statistics
        self.url_count = 0
        self.domain_set = set()
        self.browser_counts = {}
        self.extracted_urls = []  # Store URLs for CSV export
        
        # Initialize browser processors
        self.chromium_processor = ChromiumProcessor(self)
        self.firefox_processor = FirefoxProcessor(self)
        self.ie_processor = InternetExplorerProcessor(self)
        self.safari_edge_processor = SafariEdgeProcessor(self)
        self.artifact_creator = ArtifactCreator(self)
        self.report_generator = ReportGenerator(self)
        
    def startUp(self, context):
        self.context = context
        self.currentCase = Case.getCurrentCase()
        self.dataSource = None
        self.fileManager = self.currentCase.getServices().getFileManager()
        
        # Get or create custom artifact type for URL phishing analysis
        try:
            skCase = self.currentCase.getSleuthkitCase()
            
            # Try to create custom artifact type first
            try:
                self.art_url_history = skCase.addArtifactType("TSK_URL_PHISHING", "URL Phishing Analysis")
                self.log(Level.INFO, "Created custom TSK_URL_PHISHING artifact type")
            except:
                # If creation fails, try to retrieve existing custom artifact type
                try:
                    self.art_url_history = skCase.getArtifactType("TSK_URL_PHISHING")
                    self.log(Level.INFO, "Retrieved existing TSK_URL_PHISHING artifact type")
                except Exception as e:
                    self.log(Level.SEVERE, "Failed to create or retrieve custom artifact type: " + str(e))
                    # Fall back to using built-in TSK_WEB_HISTORY for compatibility
                    self.art_url_history = skCase.getArtifactType(BlackboardArtifact.ARTIFACT_TYPE.TSK_WEB_HISTORY)
                    self.log(Level.INFO, "Falling back to TSK_WEB_HISTORY artifact type")
            
            # Verify we have a valid artifact type
            if self.art_url_history is None:
                raise IngestModuleException("Failed to get any artifact type for URL analysis")
                
            # Create custom classification attribute
            self.create_classification_attribute(skCase)
            
            self.log(Level.INFO, "Successfully initialized comprehensive URL phishing extractor")
            
        except Exception as e:
            self.log(Level.SEVERE, "Error initializing custom artifact type: " + str(e))
            raise IngestModuleException("Failed to initialize custom artifact type: " + str(e))

    def create_classification_attribute(self, skCase):
        """Create custom classification attribute - REQUIRED for module operation"""
        try:
            # First try to get existing custom classification attribute
            existing_attr = None
            try:
                existing_attr = skCase.getAttributeType("TSK_PHISHING_CLASSIFICATION")
                if existing_attr is not None:
                    self.log(Level.INFO, "Custom Phishing Classification attribute already exists")
                    return
            except Exception as e:
                self.log(Level.INFO, "Custom Phishing Classification attribute not found, will create it: " + str(e))
            
            # Attribute doesn't exist or is null, so create it
            skCase.addArtifactAttributeType("TSK_PHISHING_CLASSIFICATION", 
                                           BlackboardAttribute.TSK_BLACKBOARD_ATTRIBUTE_VALUE_TYPE.STRING, 
                                           "Phishing Classification")
            self.log(Level.INFO, "Created custom Phishing Classification attribute")
            
            # Verify the attribute was created successfully
            verify_attr = skCase.getAttributeType("TSK_PHISHING_CLASSIFICATION")
            if verify_attr is None:
                raise Exception("Failed to verify custom attribute creation - attribute is still null")
            self.log(Level.INFO, "Verified custom Phishing Classification attribute is accessible")
            
        except Exception as e:
            # If creation fails, fail the module - no fallback allowed
            error_msg = "CRITICAL: Custom classification attribute creation failed: " + str(e)
            self.log(Level.SEVERE, error_msg)
            raise IngestModuleException(error_msg)

    def process(self, dataSource, progressBar):
        """Main processing method - extracts URLs from ALL browser sources"""
        self.dataSource = dataSource
        self.log(Level.INFO, "Starting Comprehensive URL Phishing Analysis")
        
        # Verify artifact type is still valid
        if self.art_url_history is None:
            self.log(Level.SEVERE, "Artifact type is None - cannot proceed")
            return IngestModule.ProcessResult.ERROR
        
        # Initialize progress
        progressBar.switchToIndeterminate()
        
        try:
            # Process Chromium-based browsers (Chrome, Edge, Brave, etc.)
            progressBar.progress("Processing Chromium-based browsers...")
            self.chromium_processor.process_all_chromium_browsers(dataSource, progressBar)
            
            if self.context.dataSourceIngestIsCancelled():
                return IngestModule.ProcessResult.OK
            
            # Process Mozilla Firefox
            progressBar.progress("Processing Firefox browsers...")
            self.firefox_processor.process_all_firefox_browsers(dataSource, progressBar)
            
            if self.context.dataSourceIngestIsCancelled():
                return IngestModule.ProcessResult.OK
            
            # Process Internet Explorer
            progressBar.progress("Processing Internet Explorer...")
            self.ie_processor.process_internet_explorer(dataSource, progressBar)
            
            if self.context.dataSourceIngestIsCancelled():
                return IngestModule.ProcessResult.OK
            
            # Process Safari (if found)
            progressBar.progress("Processing Safari browsers...")
            self.safari_edge_processor.process_safari_browsers(dataSource, progressBar)
            
            if self.context.dataSourceIngestIsCancelled():
                return IngestModule.ProcessResult.OK
            
            # Process Edge Legacy
            progressBar.progress("Processing Microsoft Edge Legacy...")
            self.safari_edge_processor.process_edge_legacy(dataSource, progressBar)
            
            if self.context.dataSourceIngestIsCancelled():
                return IngestModule.ProcessResult.OK
                
        except Exception as e:
            self.log(Level.SEVERE, "Error during URL extraction: " + str(e))
            return IngestModule.ProcessResult.ERROR
        
        # Complete processing
        try:
            # Generate comprehensive summary report and visualizations
            self.report_generator.generate_summary_report()
        except Exception as e:
            self.log(Level.WARNING, "Error generating summary report: " + str(e))
        
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA,
                                              "URL Phishing Analysis Completed", 
                                              "Successfully extracted URLs from all browser sources. Check Results Viewer -> 'URL Phishing Analysis' tab for findings with URL, Domain, Date Accessed, and Classification columns. Summary report with statistics and visualizations has been generated in the case Reports folder.")
        IngestServices.getInstance().postMessage(message)
        
        return IngestModule.ProcessResult.OK

    def create_url_artifact(self, source_file, url, timestamp, browser_type):
        """Delegate to artifact creator"""
        self.artifact_creator.create_url_artifact(source_file, url, timestamp, browser_type)

    def generate_summary_report(self):
        """Delegate to report generator"""
        self.report_generator.generate_summary_report()

    def shutDown(self):
        """Cleanup when module shuts down"""
        pass


# Required module registration
def getFactory():
    return UrlPhishingIngestModuleFactory()