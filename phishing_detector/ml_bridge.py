# -*- coding: utf-8 -*-
"""
ML Bridge for Phishing Detection Module
Handles communication with the model_package predict_bridge.py via IPC
"""

import os
import sys
import json
import threading
import time
from java.util.logging import Level
from java.io import BufferedReader, InputStreamReader, PrintWriter, OutputStreamWriter, File
from java.lang import ProcessBuilder, Process


class MLBridge:
    """Manages IPC communication with the predict_bridge.py process"""
    
    def __init__(self, module_instance):
        """Initialize ML bridge with reference to main module instance"""
        self.module = module_instance
        self.process = None
        self.process_reader = None
        self.process_writer = None
        self.is_ready = False
        self.pending_requests = {}
        self.request_counter = 0
        self.lock = threading.Lock()
        
        # Paths to model package components
        self.base_dir = os.path.dirname(os.path.dirname(__file__))
        self.model_package_dir = os.path.join(self.base_dir, "model_package")
        self.predict_bridge_path = os.path.join(self.model_package_dir, "predict_bridge.py")
        self.python_exe_path = os.path.join(self.model_package_dir, "python", "python.exe")
        
        self.module.log(Level.INFO, "ML Bridge initialized. Model package dir: " + self.model_package_dir)
        
    def start_bridge(self):
        """Start the predict_bridge.py process and wait for READY signal"""
        try:
            self.module.log(Level.INFO, "Starting ML Bridge initialization...")
            
            # Check if model package exists
            if not os.path.exists(self.model_package_dir):
                self.module.log(Level.SEVERE, "Model package directory not found: " + self.model_package_dir)
                return False
                
            if not os.path.exists(self.predict_bridge_path):
                self.module.log(Level.SEVERE, "Predict bridge script not found: " + self.predict_bridge_path)
                return False
                
            if not os.path.exists(self.python_exe_path):
                self.module.log(Level.SEVERE, "Python executable not found: " + self.python_exe_path)
                return False
            
            self.module.log(Level.INFO, "All required files found, starting process...")
            
            # Start the predict_bridge.py process using the embedded Python
            self.module.log(Level.INFO, "Starting predict_bridge.py with embedded Python: " + self.python_exe_path)
            
            # Use Java ProcessBuilder for better control
            pb = ProcessBuilder([self.python_exe_path, self.predict_bridge_path])
            pb.directory(File(self.model_package_dir))
            pb.redirectErrorStream(True)  # Merge stderr with stdout
            
            self.module.log(Level.INFO, "Starting process with command: " + str(pb.command()))
            self.process = pb.start()
            self.module.log(Level.INFO, "Process started successfully")
            
            # Set up communication streams
            self.process_reader = BufferedReader(InputStreamReader(self.process.getInputStream()))
            self.process_writer = PrintWriter(OutputStreamWriter(self.process.getOutputStream()), True)
            self.module.log(Level.INFO, "Communication streams established")
            
            # Start reader thread
            reader_thread = threading.Thread(target=self._reader_thread)
            reader_thread.daemon = True
            reader_thread.start()
            self.module.log(Level.INFO, "Reader thread started")
            
            # Wait for READY signal with timeout
            timeout = 60  # 60 seconds timeout (increased for model loading)
            start_time = time.time()
            
            self.module.log(Level.INFO, "Waiting for READY signal from predict_bridge.py...")
            while not self.is_ready and (time.time() - start_time) < timeout:
                time.sleep(0.1)
                
            if self.is_ready:
                self.module.log(Level.INFO, "ML Bridge successfully started and ready for predictions")
                return True
            else:
                self.module.log(Level.SEVERE, "ML Bridge failed to start - timeout waiting for READY signal")
                self.stop_bridge()
                return False
                
        except Exception as e:
            self.module.log(Level.SEVERE, "Error starting ML Bridge: " + str(e))
            self.stop_bridge()
            return False
    
    def _reader_thread(self):
        """Background thread to read responses from predict_bridge.py"""
        try:
            self.module.log(Level.INFO, "Reader thread started, waiting for output...")
            while True:
                line = self.process_reader.readLine()
                if line is None:
                    self.module.log(Level.WARNING, "Reader thread: No more input, process may have ended")
                    break
                    
                line = line.strip()
                if not line:
                    continue
                    
                self.module.log(Level.INFO, "Reader thread received: " + line)
                
                # Check for READY signal
                if line == "READY":
                    self.is_ready = True
                    self.module.log(Level.INFO, "Received READY signal from predict_bridge.py")
                    continue
                
                # Skip log messages (lines that start with timestamp)
                if line.startswith("[") and "]" in line and "INFO" in line:
                    self.module.log(Level.INFO, "Bridge log: " + line)
                    continue
                
                # Parse JSON response (only for actual JSON responses)
                try:
                    response = json.loads(line)
                    self._handle_response(response)
                except ValueError:
                    # Not JSON, might be other output - log it but don't treat as error
                    self.module.log(Level.INFO, "Bridge output (non-JSON): " + line)
                    
        except Exception as e:
            self.module.log(Level.WARNING, "Error in reader thread: " + str(e))
        finally:
            self.is_ready = False
    
    def _handle_response(self, response):
        """Handle response from predict_bridge.py"""
        try:
            if "url" in response and "prediction" in response:
                url = response["url"]
                prediction = response["prediction"]
                
                # Map prediction to classification
                classification = self._map_prediction_to_classification(prediction)
                
                # Store result for retrieval
                with self.lock:
                    if url in self.pending_requests:
                        self.pending_requests[url] = classification
                        
            elif "error" in response:
                self.module.log(Level.WARNING, "Bridge error: " + str(response['error']))
                
        except Exception as e:
            self.module.log(Level.WARNING, "Error handling bridge response: " + str(e))
    
    def _map_prediction_to_classification(self, prediction):
        """Map ML model prediction to classification string"""
        if prediction == "good":
            return "SAFE"
        elif prediction == "bad":
            return "PHISHING"
        else:
            return "UNCERTAIN"
    
    def predict_url(self, url):
        """Send URL to predict_bridge.py for classification"""
        try:
            if not self.is_ready:
                self.module.log(Level.WARNING, "ML Bridge not ready, returning PENDING")
                return "PENDING"
            
            # Send URL to bridge
            self.process_writer.println(url)
            self.process_writer.flush()
            
            # Wait for response with timeout
            timeout = 10  # 10 seconds timeout per URL
            start_time = time.time()
            
            with self.lock:
                self.pending_requests[url] = None  # Mark as pending
                
            while (time.time() - start_time) < timeout:
                with self.lock:
                    if url in self.pending_requests and self.pending_requests[url] is not None:
                        result = self.pending_requests[url]
                        del self.pending_requests[url]
                        return result
                        
                time.sleep(0.1)
            
            # Timeout - clean up and return error
            with self.lock:
                if url in self.pending_requests:
                    del self.pending_requests[url]
                    
            self.module.log(Level.WARNING, "Timeout waiting for prediction of URL: " + str(url)[:50])
            return "TIMEOUT"
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error predicting URL " + str(url)[:50] + ": " + str(e))
            return "ERROR"
    
    def stop_bridge(self):
        """Stop the predict_bridge.py process"""
        try:
            if self.process_writer:
                self.process_writer.println("EXIT")
                self.process_writer.flush()
                self.process_writer.close()
                
            if self.process:
                # Wait for process to terminate
                self.process.waitFor()
                
            self.is_ready = False
            self.module.log(Level.INFO, "ML Bridge stopped")
            
        except Exception as e:
            self.module.log(Level.WARNING, "Error stopping ML Bridge: " + str(e))
        finally:
            self.process = None
            self.process_reader = None
            self.process_writer = None
