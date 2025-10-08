# -*- coding: utf-8 -*-
"""
Artifact Creation Utilities for Phishing Detection Module
Handles creation of blackboard artifacts and URL classification
"""

import re
from java.util.logging import Level

from org.sleuthkit.datamodel import BlackboardArtifact, BlackboardAttribute
from org.sleuthkit.autopsy.casemodule import Case


class ArtifactCreator:
    """Creates artifacts for URLs found during browser processing - VERSION 2.2"""
    
    def __init__(self, module_instance):
        """Initialize with reference to main module instance"""
        self.module = module_instance
        
    def create_url_artifact(self, source_file, url, timestamp, browser_type):
        """Create blackboard artifact for URL phishing analysis using the working pattern"""
        try:
            # Determine a safe module name for Autopsy UI attribution
            module_name = getattr(getattr(self.module, '__class__', object), 'moduleName', None) or "Comprehensive URL Phishing Extractor"
            # Verify artifact type is valid before proceeding
            if self.module.art_url_history is None:
                self.module.log(Level.SEVERE, "Artifact type is None - skipping URL: " + str(url)[:50])
                return
                
            # Debug logging
            self.module.log(Level.INFO, "Creating artifact for URL: " + str(url)[:100] + " from " + browser_type)
            
            # Extract domain from URL
            domain = self.extract_domain(url)
            
            # Validate required fields before creating artifact
            if not url or not url.strip():
                self.module.log(Level.WARNING, "Skipping artifact creation - URL is empty or null")
                return
                
            if not browser_type or not browser_type.strip():
                self.module.log(Level.WARNING, "Skipping artifact creation - Browser type is empty or null")
                return
                
            # Check if we have meaningful data - require valid timestamp
            if timestamp <= 0:
                self.module.log(Level.WARNING, "Skipping artifact creation - No valid date accessed (timestamp: " + str(timestamp) + ")")
                return
            
            # Get phishing classification (blank for now as requested)
            classification = self.classify_url_phishing(url)
            
            # Track statistics
            self.module.url_count += 1
            if domain:
                self.module.domain_set.add(domain)
            self.module.browser_counts[browser_type] = self.module.browser_counts.get(browser_type, 0) + 1
            
            # Store URL data for CSV export
            url_data = {
                'url': url,
                'domain': domain,
                'timestamp': timestamp,
                'browser': browser_type,
                'classification': classification,
                'file_path': source_file.getParentPath() + source_file.getName()
            }
            self.module.extracted_urls.append(url_data)
            
            # Create artifact using the working pattern from fixed_autopsy_module.py
            try:
                # First try using getTypeID() if available
                art = source_file.newArtifact(self.module.art_url_history.getTypeID())
            except:
                try:
                    # If getTypeID() fails, try using the artifact type directly
                    art = source_file.newArtifact(self.module.art_url_history)
                except:
                    # Final fallback - get the artifact type by name and use its ID
                    skCase = Case.getCurrentCase().getSleuthkitCase()
                    artifact_type = skCase.getArtifactType("TSK_URL_PHISHING")
                    art = source_file.newArtifact(artifact_type.getTypeID())
            
            # Add attributes using standard Autopsy attribute types (working pattern)
            attributes = []
            
            # URL - use standard URL attribute
            att_url = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_URL,
                                         module_name, url)
            attributes.append(att_url)
            
            # Domain - use standard domain attribute
            if domain:
                att_domain = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN,
                                               module_name, domain)
                attributes.append(att_domain)
            
            # Date Accessed - use standard datetime attribute  
            if timestamp > 0:
                att_date = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DATETIME_ACCESSED,
                                             module_name, int(timestamp))
                attributes.append(att_date)
            
            # Browser Source - use program name attribute
            att_browser = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME,
                                            module_name, browser_type)
            attributes.append(att_browser)
            
            # Classification - use custom attribute (REQUIRED - no fallback)
            skCase = Case.getCurrentCase().getSleuthkitCase()
            try:
                # Get custom classification attribute - this will fail if not properly created
                classification_attr_type = skCase.getAttributeType("TSK_PHISHING_CLASSIFICATION")
                if classification_attr_type is None:
                    error_msg = "CRITICAL: Custom classification attribute TSK_PHISHING_CLASSIFICATION is null - attribute may not exist"
                    self.module.log(Level.SEVERE, error_msg)
                    raise Exception(error_msg)
                
                att_classification = BlackboardAttribute(classification_attr_type,
                                                       module_name, 
                                                       classification if classification else "")
                attributes.append(att_classification)
                self.module.log(Level.INFO, "Using custom TSK_PHISHING_CLASSIFICATION attribute for classification")
            except Exception as e:
                # This should never happen if module startup succeeded, but fail hard if it does
                error_msg = "CRITICAL: Custom classification attribute not available: " + str(e)
                self.module.log(Level.SEVERE, error_msg)
                raise Exception(error_msg)
            
            # Add description for better identification
            att_description = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DESCRIPTION,
                                                module_name, 
                                                "Browser URL extracted for phishing analysis from " + browser_type)
            attributes.append(att_description)
            
            # Add all attributes to the artifact
            art.addAttributes(attributes)
            
            # Index the artifact for keyword searching (working pattern)
            try:
                blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
                blackboard.indexArtifact(art)
            except Exception as e:
                self.module.log(Level.WARNING, "Error indexing artifact (method may not exist in this Autopsy version): " + str(e))
            
            # Post artifact to blackboard for UI updates (working pattern)
            try:
                blackboard = Case.getCurrentCase().getSleuthkitCase().getBlackboard()
                blackboard.postArtifact(art, module_name)
                self.module.log(Level.INFO, "Successfully created and posted artifact for URL: " + str(url)[:50])
            except Exception as e:
                self.module.log(Level.WARNING, "Error posting artifact event: " + str(e))
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error creating URL artifact for " + str(url)[:50] + ": " + str(e))

    def extract_domain(self, url):
        """Extract domain name from URL"""
        try:
            if not url or not url.strip():
                return ""
            
            # Handle URLs without protocol
            if not url.startswith(('http://', 'https://', 'ftp://')):
                url = 'http://' + url
            
            # Simple URL parsing without urlparse
            # Remove protocol
            if '://' in url:
                url = url.split('://', 1)[1]
            
            # Extract domain part (before first slash or query)
            domain = url.split('/')[0].split('?')[0].split('#')[0]
            
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Remove www. prefix if present
            if domain.startswith('www.'):
                domain = domain[4:]
                
            return domain
        except Exception as e:
            self.module.log(Level.WARNING, "Error extracting domain from URL: " + str(url) + " - " + str(e))
            return ""

    def classify_url_phishing(self, url):
        """
        Phishing classification function - Ready for ML model integration
        
        This function is prepared for your phishing detection model.
        Currently returns "PENDING" as a placeholder.
        
        Args:
            url (str): The URL to classify
            
        Returns:
            str: Classification result - currently "PENDING", ready for your model
        """
        
        # TODO: Add your ML model integration here
        # 
        # When you're ready to integrate your ML model, replace this section with:
        # 
        # try:
        #     # Load your trained model (do this once in __init__ for performance)
        #     # model = load_model('path/to/your/phishing_model.pkl')
        #     
        #     # Extract features from URL
        #     # features = extract_url_features(url)
        #     
        #     # Get prediction from your model
        #     # prediction = model.predict([features])[0]
        #     # confidence = model.predict_proba([features])[0].max()
        #     
        #     # Return classification based on prediction
        #     # if prediction == 1 and confidence > 0.8:
        #     #     return "PHISHING"
        #     # elif prediction == 1 and confidence > 0.6:
        #     #     return "SUSPICIOUS" 
        #     # elif prediction == 0:
        #     #     return "SAFE"
        #     # else:
        #     #     return "UNCERTAIN"
        #         
        # except Exception as e:
        #     self.module.log(Level.WARNING, "ML model classification failed: " + str(e))
        #     return "ERROR"
        
        return "PENDING"  # Placeholder classification - will show in results table