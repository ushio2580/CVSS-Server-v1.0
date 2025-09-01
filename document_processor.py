"""
Document Processor for CVSS Server
==================================

This module handles document uploads (Word, PDF) and extracts CVSS metrics
from the text content using natural language processing and pattern matching.
"""

import re
import io
import os
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import json

try:
    from docx import Document
    from PyPDF2 import PdfReader
    import pdfplumber
    DEPENDENCIES_AVAILABLE = True
except ImportError:
    DEPENDENCIES_AVAILABLE = False
    print("Warning: Document processing dependencies not available. Install with: pip install python-docx PyPDF2 pdfplumber")


class DocumentProcessor:
    """Processes uploaded documents to extract CVSS metrics."""
    
    def __init__(self):
        self.cvss_patterns = {
            # Attack Vector patterns
            'AV': {
                'N': [r'\bnetwork\b', r'\bremote\b', r'\bover\s+network\b', r'\bnetwork\s+accessible\b'],
                'A': [r'\badjacent\b', r'\bsame\s+network\b', r'\blocal\s+network\b', r'\bsubnet\b'],
                'L': [r'\blocal\b', r'\bon\s+system\b', r'\brequires\s+local\s+access\b'],
                'P': [r'\bphysical\b', r'\bphysical\s+access\b', r'\brequires\s+physical\s+access\b']
            },
            # Attack Complexity patterns
            'AC': {
                'L': [r'\blow\s+complexity\b', r'\bsimple\b', r'\beasy\b', r'\btrivial\b'],
                'H': [r'\bhigh\s+complexity\b', r'\bcomplex\b', r'\bdifficult\b', r'\brequires\s+special\b']
            },
            # Privileges Required patterns
            'PR': {
                'N': [r'\bno\s+privileges\b', r'\bunprivileged\b', r'\bno\s+authentication\b'],
                'L': [r'\blow\s+privileges\b', r'\bbasic\s+user\b', r'\buser\s+level\b'],
                'H': [r'\bhigh\s+privileges\b', r'\badmin\b', r'\broot\b', r'\belevated\b']
            },
            # User Interaction patterns
            'UI': {
                'N': [r'\bno\s+user\s+interaction\b', r'\bautomatic\b', r'\bno\s+user\s+action\b'],
                'R': [r'\brequires\s+user\s+interaction\b', r'\buser\s+must\s+click\b', r'\buser\s+action\b']
            },
            # Scope patterns
            'S': {
                'U': [r'\bunchanged\s+scope\b', r'\bsame\s+component\b', r'\bwithin\s+component\b'],
                'C': [r'\bchanged\s+scope\b', r'\bdifferent\s+component\b', r'\bcross\s+component\b']
            },
            # Impact patterns
            'C': {
                'N': [r'\bno\s+confidentiality\s+impact\b', r'\bno\s+data\s+disclosure\b'],
                'L': [r'\blow\s+confidentiality\s+impact\b', r'\bminor\s+data\s+leak\b'],
                'H': [r'\bhigh\s+confidentiality\s+impact\b', r'\bcomplete\s+data\s+disclosure\b']
            },
            'I': {
                'N': [r'\bno\s+integrity\s+impact\b', r'\bno\s+data\s+modification\b'],
                'L': [r'\blow\s+integrity\s+impact\b', r'\bminor\s+data\s+modification\b'],
                'H': [r'\bhigh\s+integrity\s+impact\b', r'\bcomplete\s+data\s+modification\b']
            },
            'A': {
                'N': [r'\bno\s+availability\s+impact\b', r'\bno\s+service\s+disruption\b'],
                'L': [r'\blow\s+availability\s+impact\b', r'\bminor\s+service\s+disruption\b'],
                'H': [r'\bhigh\s+availability\s+impact\b', r'\bcomplete\s+service\s+disruption\b']
            }
        }
    
    def extract_text_from_docx(self, file_content: bytes) -> str:
        """Extract text from Word document."""
        if not DEPENDENCIES_AVAILABLE:
            raise ImportError("python-docx not available")
        
        try:
            doc = Document(io.BytesIO(file_content))
            text = []
            for paragraph in doc.paragraphs:
                text.append(paragraph.text)
            return '\n'.join(text)
        except Exception as e:
            raise ValueError(f"Error reading Word document: {e}")
    
    def extract_text_from_pdf(self, file_content: bytes) -> str:
        """Extract text from PDF document."""
        if not DEPENDENCIES_AVAILABLE:
            raise ImportError("PyPDF2/pdfplumber not available")
        
        try:
            # Try pdfplumber first (better text extraction)
            with pdfplumber.open(io.BytesIO(file_content)) as pdf:
                text = []
                for page in pdf.pages:
                    page_text = page.extract_text()
                    if page_text:
                        text.append(page_text)
                return '\n'.join(text)
        except Exception:
            try:
                # Fallback to PyPDF2
                reader = PdfReader(io.BytesIO(file_content))
                text = []
                for page in reader.pages:
                    text.append(page.extract_text())
                return '\n'.join(text)
            except Exception as e:
                raise ValueError(f"Error reading PDF document: {e}")
    
    def extract_text_from_file(self, file_content: bytes, filename: str) -> str:
        """Extract text from uploaded file based on file type."""
        filename_lower = filename.lower()
        
        if filename_lower.endswith('.docx'):
            return self.extract_text_from_docx(file_content)
        elif filename_lower.endswith('.pdf'):
            return self.extract_text_from_pdf(file_content)
        else:
            raise ValueError(f"Unsupported file type: {filename}")
    
    def detect_cvss_metrics(self, text: str) -> Dict[str, str]:
        """Detect CVSS metrics from text using pattern matching."""
        text_lower = text.lower()
        detected_metrics = {}
        
        # Initialize with default values
        default_metrics = {
            'AV': 'L', 'AC': 'H', 'PR': 'N', 'UI': 'N', 
            'S': 'U', 'C': 'N', 'I': 'N', 'A': 'N'
        }
        
        # Detect each metric
        for metric, values in self.cvss_patterns.items():
            best_match = None
            max_matches = 0
            
            for value, patterns in values.items():
                matches = 0
                for pattern in patterns:
                    if re.search(pattern, text_lower, re.IGNORECASE):
                        matches += 1
                
                if matches > max_matches:
                    max_matches = matches
                    best_match = value
            
            if best_match:
                detected_metrics[metric] = best_match
            else:
                detected_metrics[metric] = default_metrics[metric]
        
        return detected_metrics
    
    def extract_cve_id(self, text: str) -> Optional[str]:
        """Extract CVE ID from text."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        match = re.search(cve_pattern, text, re.IGNORECASE)
        return match.group() if match else None
    
    def extract_title(self, text: str) -> str:
        """Extract potential title from text."""
        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if line and len(line) > 10 and len(line) < 200:
                # Skip common headers
                if not any(header in line.lower() for header in ['abstract', 'summary', 'introduction', 'description']):
                    return line[:200]  # Limit length
        return "Document Analysis"
    
    def process_document(self, file_content: bytes, filename: str) -> Dict[str, any]:
        """Process uploaded document and extract CVSS information."""
        try:
            # Extract text from document
            text = self.extract_text_from_file(file_content, filename)
            
            # Extract CVSS metrics
            metrics = self.detect_cvss_metrics(text)
            
            # Extract additional information
            cve_id = self.extract_cve_id(text)
            title = self.extract_title(text)
            
            return {
                'success': True,
                'text': text[:1000] + '...' if len(text) > 1000 else text,  # Truncate for display
                'metrics': metrics,
                'cve_id': cve_id,
                'title': title,
                'filename': filename
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'filename': filename
            }


# Global instance
document_processor = DocumentProcessor()
